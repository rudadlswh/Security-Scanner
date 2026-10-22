"""제품 입력 길이 검사: 작은 요청은 바이트 상한, 큰 요청은 고정 Qwen 어휘로 로컬 실측.

실측은 별도 프로세스에서 vocab_only로 수행한다. 가중치/생성 컨텍스트를 만들지 않으며
기존 실험 자료는 읽기 전용 보정 근거로만 사용한다. 요청/코드는 파일에 저장하지 않는다.
"""
from __future__ import annotations

import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys

from .workspace import ProductError, REPO, digest, load_json

MODEL_DIGEST = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
LAYER_DIGEST = "sha256:02d45dc1cf451ba2475ac33b301c2dd8f985abe4c182ce04a1f2f5bf0260278d"
DLL_DIGEST = "00ea020d8a1fe830eafd030ff0fc80eee339c7bce9916a53a3078de97c4aee8d"
SERVER_VERSION = "0.40.4"
CALIBRATION = (
    ("pf-1-P_FULL", "ca0bb5185d66c4367574100dee74813ea914076f1a9840c36e840adaeae77bfd", 917),
    ("pf-2-P_MIN", "abb8d62d893f7f5491689f0498fa4faa541d60c5007e7456efd97dcf7e44f736", 615),
)


def render(request: dict) -> str:
    messages = request["messages"]
    if (len(messages) != 2 or [m["role"] for m in messages] != ["system", "user"]
            or request.get("think") is not False):
        raise ProductError("TOKENIZER_RENDER_PROFILE_UNSUPPORTED")
    system, user = (m["content"].strip() for m in messages)
    return ("<|im_start|>system\n" + system + "<|im_end|>\n<|im_start|>user\n" + user
            + "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n")


def measure_input(request: dict, model: dict) -> dict:
    # 기존 바이트 상한을 유지하며, 실측할 수 없을 때 비율 추정으로 검사를 완화하지 않는다.
    upper = len(json.dumps({"messages": request["messages"], "format": request["format"]}, ensure_ascii=False).encode("utf-8")) + 2048
    options = request["options"]
    output, context, margin = options["num_predict"], options["num_ctx"], 512
    metadata = {"input_utf8_token_upper_bound": upper, "output_reservation": output,
                "context_tokens": context, "extra_margin": margin, "exact_local_token_count": None,
                "token_method": "CONSERVATIVE_UTF8_BYTE_UPPER_BOUND_QWEN_ONLY"}
    if upper + output + margin <= context:
        return {**metadata, "remaining_tokens": context - upper - output - margin}
    if model.get("name") != "qwen3.5:9b" or model.get("digest", "").removeprefix("sha256:") != MODEL_DIGEST:
        raise ProductError("TOKENIZER_PROFILE_UNAVAILABLE: byte bound exceeds context; no request sent")
    try:
        result = subprocess.run([sys.executable, "-m", "localcode_review_mcp.token_budget"],
                                input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
                                capture_output=True, cwd=REPO, timeout=120)
    except subprocess.TimeoutExpired:
        raise ProductError("LOCAL_TOKENIZER_TIMEOUT") from None
    if result.returncode:
        # 자식 프로세스와 외부 라이브러리의 stderr에는 경로가 포함될 수 있어 노출하지 않는다.
        try:
            failure = json.loads(result.stdout[:16_384]).get("error")
        except (ValueError, AttributeError):
            failure = None
        allowed = {"TOKENIZER_PLATFORM_OR_MODEL_UNSUPPORTED", "TOKENIZER_BINARY_CHANGED",
                   "TOKENIZER_VOCABULARY_CHANGED", "TOKENIZER_ABI_CHANGED", "TOKENIZER_VOCABULARY_LOAD_FAILED",
                   "TOKENIZER_COUNT_INVALID", "TOKENIZER_CALIBRATION_FAILED", "TOKENIZER_RENDER_PROFILE_UNSUPPORTED"}
        code = failure if failure in allowed else "LOCAL_TOKENIZER_FAILED"
        raise ProductError(code + ": pinned vocabulary/profile unavailable; no request sent")
    if len(result.stdout) > 16_384:
        raise ProductError("LOCAL_TOKENIZER_OUTPUT_INVALID")
    measured = json.loads(result.stdout)
    for key in ("local_rendered_input_tokens", "schema_separate_tokens"):
        if type(measured.get(key)) is not int or measured[key] <= 0:
            raise ProductError("LOCAL_TOKENIZER_OUTPUT_INVALID")
    if measured.get("required_server_version") != SERVER_VERSION:
        raise ProductError("LOCAL_TOKENIZER_OUTPUT_INVALID")
    used = measured["local_rendered_input_tokens"] + measured["schema_separate_tokens"]
    metadata.update(measured, token_method="PINNED_QWEN35_LOCAL_VOCABULARY_WITH_CALIBRATED_RENDERER",
                    exact_local_token_count=measured["local_rendered_input_tokens"],
                    remaining_tokens=context - used - output - margin,
                    local_measurement_is_server_count=False)
    if metadata["remaining_tokens"] < 0:
        raise ProductError("CONTEXT_BUDGET_EXCEEDED: measured input and reservations exceed context; no silent truncation")
    return metadata


class ModelParams(C.Structure):
    # SHA-256으로 고정한 libllama.dll의 ABI만 지원한다. DLL이 바뀌면 실측을 중단한다.
    _fields_ = [("devices", C.c_void_p), ("tensor_buft_overrides", C.c_void_p),
                ("n_gpu_layers", C.c_int32), ("split_mode", C.c_int),
                ("load_mode", C.c_int), ("lazy_mode", C.c_int), ("main_gpu", C.c_int32),
                ("tensor_split", C.c_void_p), ("progress_callback", C.c_void_p),
                ("progress_callback_user_data", C.c_void_p), ("kv_overrides", C.c_void_p),
                ("vocab_only", C.c_bool), ("check_tensors", C.c_bool),
                ("use_extra_bufts", C.c_bool), ("no_host", C.c_bool),
                ("no_alloc", C.c_bool), ("load_mtp", C.c_bool)]


def vocabulary_measure(request: dict) -> dict:
    if os.name != "nt" or C.sizeof(ModelParams) != 80 or request.get("model") != "qwen3.5:9b":
        raise ProductError("TOKENIZER_PLATFORM_OR_MODEL_UNSUPPORTED")
    candidates = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Ollama/lib/ollama",
                  Path.home() / "AppData/Local/Programs/Ollama/lib/ollama"]
    folder = next((p for p in candidates if (p / "libllama.dll").is_file()), None)
    if folder is None or digest((folder / "libllama.dll").read_bytes()) != DLL_DIGEST:
        raise ProductError("TOKENIZER_BINARY_CHANGED")
    models = Path(os.environ.get("OLLAMA_MODELS", str(Path.home() / ".ollama/models")))
    manifest = load_json(models / "manifests/registry.ollama.ai/library/qwen3.5/9b")
    layers = [x for x in manifest["layers"] if x["mediaType"] == "application/vnd.ollama.image.model"]
    if len(layers) != 1 or layers[0]["digest"] != LAYER_DIGEST:
        raise ProductError("TOKENIZER_VOCABULARY_CHANGED")
    blob = models / "blobs" / LAYER_DIGEST.replace(":", "-")
    if blob.stat().st_size != layers[0]["size"]:
        raise ProductError("TOKENIZER_VOCABULARY_CHANGED")
    with os.add_dll_directory(str(folder)):
        lib = C.CDLL(str(folder / "libllama.dll"))
        lib.llama_version.restype = C.c_char_p
        if lib.llama_version() != b"0.6.0-dev":
            raise ProductError("TOKENIZER_ABI_CHANGED")
        lib.llama_model_default_params.restype = ModelParams
        lib.llama_model_load_from_file.argtypes = [C.c_char_p, ModelParams]
        lib.llama_model_load_from_file.restype = C.c_void_p
        lib.llama_model_get_vocab.argtypes = [C.c_void_p]
        lib.llama_model_get_vocab.restype = C.c_void_p
        lib.llama_model_free.argtypes = [C.c_void_p]
        lib.llama_tokenize.argtypes = [C.c_void_p, C.c_char_p, C.c_int32, C.POINTER(C.c_int32), C.c_int32, C.c_bool, C.c_bool]
        lib.llama_tokenize.restype = C.c_int32
        callback = C.CFUNCTYPE(None, C.c_int, C.c_char_p, C.c_void_p)(lambda *_: None)
        lib.llama_log_set.argtypes = [type(callback), C.c_void_p]
        lib.llama_log_set(callback, None)
        params = lib.llama_model_default_params()
        params.vocab_only = True
        params.n_gpu_layers = 0
        model = lib.llama_model_load_from_file(os.fsencode(blob), params)
        if not model:
            raise ProductError("TOKENIZER_VOCABULARY_LOAD_FAILED")
        try:
            vocab = lib.llama_model_get_vocab(model)
            if not vocab:
                raise ProductError("TOKENIZER_VOCABULARY_LOAD_FAILED")

            def count(text):
                data = text.encode("utf-8")
                size = abs(lib.llama_tokenize(vocab, data, len(data), None, 0, True, True))
                if not 0 < size <= len(data) + 100:
                    raise ProductError("TOKENIZER_COUNT_INVALID")
                tokens = (C.c_int32 * size)()
                if lib.llama_tokenize(vocab, data, len(data), tokens, size, True, True) != size:
                    raise ProductError("TOKENIZER_COUNT_INVALID")
                return size

            for name, checksum, expected in CALIBRATION:
                path = REPO / "results/20261018-pf01-9b-001" / name / "request.json"
                if digest(path.read_bytes()) != checksum or count(render(load_json(path))) != expected:
                    raise ProductError("TOKENIZER_CALIBRATION_FAILED")
            return {"local_rendered_input_tokens": count(render(request)),
                    "schema_separate_tokens": count(json.dumps(request["format"], ensure_ascii=False, separators=(",", ":"))),
                    "required_server_version": SERVER_VERSION, "tokenizer_dll_sha256": DLL_DIGEST,
                    "vocabulary_layer_digest": LAYER_DIGEST, "calibration_cases": 2,
                    "model_calls": 0, "network_calls": 0}
        finally:
            lib.llama_model_free(model)


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(4_194_305)
        if len(raw) > 4_194_304:
            raise ProductError("TOKENIZER_INPUT_LIMIT")
        print(json.dumps(vocabulary_measure(json.loads(raw))))
    except ProductError as error:
        print(json.dumps({"error": str(error)}))
        raise SystemExit(2)
    except Exception:
        print("LOCAL_TOKENIZER_WORKER_FAILED", file=sys.stderr)
        raise SystemExit(2)
