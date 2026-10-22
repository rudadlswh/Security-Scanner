/*
 * [한글 기능 설명]
 * 기능: JSON 읽기·파싱·직렬화와 원문/정규화 SHA-256 계산을 공통 제공한다.
 * 시작점/입력: 파일 경로, JSON 문자열 또는 JsonNode.
 * 이어지는 기능: read/parse → object/array 구성 → writeNew; canonicalSha는 정규화 내용 비교에 사용.
 * 주의: 원문 바이트 해시와 정규화 JSON 해시는 목적이 다르며 writeNew는 기존 파일을 덮어쓰지 않는다.
 */

package dev.localcodereview;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public final class Json {
    private Json() {}
    public static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public static JsonNode read(Path path) throws IOException { return parse(Files.readString(path)); }
    public static JsonNode parse(String value) throws IOException {
        JsonNode node = MAPPER.readTree(value);
        if (node == null) throw new IOException("Empty JSON document");
        return node;
    }
    public static ObjectNode object() { return MAPPER.createObjectNode(); }
    public static ArrayNode array() { return MAPPER.createArrayNode(); }
    public static byte[] bytes(JsonNode value) throws IOException {
        return (MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n")
                .getBytes(StandardCharsets.UTF_8);
    }
    public static void writeNew(Path path, JsonNode value) throws IOException {
        Files.write(path, bytes(value), StandardOpenOption.CREATE_NEW);
    }
    public static String sha(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
    public static String sha(String text) { return sha(text.getBytes(StandardCharsets.UTF_8)); }
    public static JsonNode canonical(JsonNode node) {
        if (node.isObject()) {
            ObjectNode sorted = object();
            TreeSet<String> names = new TreeSet<>();
            node.fieldNames().forEachRemaining(names::add);
            names.forEach(name -> sorted.set(name, canonical(node.get(name))));
            return sorted;
        }
        if (node.isArray()) {
            ArrayNode values = array();
            node.forEach(item -> values.add(canonical(item)));
            return values;
        }
        return node;
    }
    public static String canonicalSha(JsonNode node) throws IOException {
        return sha(MAPPER.writeValueAsBytes(canonical(node)));
    }
}
