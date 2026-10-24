"""운영자가 등록한 Ed25519 공개키로 검토 서명을 확인한다. 실명/미참여의 증명은 아니다."""
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .contracts import canonical_id, exact_fields, unique_ids
from .workspace import ProductError, digest

DOMAIN = b'LocalCodeReview/audit-review/2\x00'


def signing_bytes(review):
    unsigned = {k:v for k,v in review.items() if k != 'signature'}
    return DOMAIN + bytes.fromhex(digest(unsigned))


def trusted_registry(policy):
    registry = policy.get('trusted_reviewers', {})
    if not isinstance(registry,dict) or not 1 <= len(registry) <= 100:
        raise ProductError('AUDIT_TRUSTED_KEYS_REQUIRED')
    unique_ids(list(registry))
    public_keys = set()
    for key_id, row in registry.items():
        exact_fields(row, {'principal_id','public_key'})
        canonical_id(row['principal_id'])
        try:
            raw = base64.b64decode(row['public_key'],validate=True)
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError,TypeError): raise ProductError('AUDIT_PUBLIC_KEY_INVALID') from None
        if raw in public_keys: raise ProductError('AUDIT_KEY_ALIAS_COLLISION')
        public_keys.add(raw)
    return registry


def verify_signature(policy, report, review):
    registry = trusted_registry(policy)
    if report.get('review_policy_sha256') != digest(registry):
        raise ProductError('AUDIT_TRUST_POLICY_CHANGED')
    proof = review.get('signature')
    exact_fields(proof, {'key_id','value'})
    key_id = canonical_id(proof['key_id'])
    if key_id not in registry: raise ProductError('AUDIT_UNTRUSTED_SIGNER')
    principal = registry[key_id]['principal_id']
    principals = {row['principal_id'].casefold() for row in registry.values()}
    author_ids = unique_ids(report.get('authors', []))
    if not author_ids or not author_ids <= principals:
        raise ProductError('AUDIT_AUTHOR_PRINCIPALS_REQUIRED')
    if principal.casefold() in author_ids: raise ProductError('INDEPENDENT_REVIEWER_REQUIRED')
    if principal != review.get('reviewer_id'): raise ProductError('AUDIT_SIGNER_IDENTITY_MISMATCH')
    try:
        raw = base64.b64decode(proof['value'],validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(registry[key_id]['public_key'],validate=True))
        key.verify(raw,signing_bytes(review))
    except (InvalidSignature,ValueError,TypeError): raise ProductError('AUDIT_SIGNATURE_INVALID') from None
    return {'status':'REGISTERED_ED25519_KEY_VERIFIED','principal_id':principal,
            'key_id':key_id,'public_key_sha256':digest(base64.b64decode(registry[key_id]['public_key'])),
            'policy_sha256':digest(registry),'real_world_identity_proven':False,'nonparticipation_proven':False}
