# TC-JARVIS Ledger Integration Contract

`registry/oss-registry.json`의 각 record는 상위 레저에 다음처럼 투영한다.

| Admission field | Jarvis ledger field | 규칙 |
| --- | --- | --- |
| `admission_id` | `source_record_id` | 전역적으로 불변 |
| `component` | `component` | 사람에게 보이는 이름 |
| `source.source_url` | `source_url` | HTTPS 원문 URL |
| `source.immutable_ref` | `pinned_ref` | 변경 시 신규 심사 |
| `license` | `license_expression` | SPDX 또는 승인 예외 |
| `status` | `admission_status` | Harness의 권위 있는 상태 |
| `jarvis_ledger.ledger_id` | `id` | `oss.` prefix 필수 |
| `evidence_refs` | `evidence_refs` | 상대 경로 그대로 유지 |

상위 레저에는 Harness 검증 후 아래 reference를 추가한다.

```json
{
  "id": "oss.example-approved-git-source",
  "admission_status": "APPROVED",
  "evidence_refs": [
    "TC-OSS-ADMISSION-HARNESS/evidence/example-approved-git-source.json",
    "TC-OSS-ADMISSION-HARNESS/evidence/validation-result.json"
  ]
}
```

`validation-result.json`이 `PASS`가 아닌 record는 TC-JARVIS에서 invocable dependency 또는 reusable source로 등록할 수 없다.

## 발견 증거 (P3)

`evidence/discovery-result.json`은 아직 승인되지 않은 유입 후보를 상위 레저에 노출한다. 이 파일은
레저 record를 만들지 않으며, 심사 대기열의 입력으로만 쓴다.

| Discovery field | Jarvis ledger field | 규칙 |
| --- | --- | --- |
| `candidate_id` | `candidate_id` | 심사 큐 내에서만 유효한 임시 식별자 |
| `source_url` | `source_url` | 정규화된 HTTPS URL |
| `immutable_ref` | `pinned_ref` | `null`이면 고정되지 않은 후보 |
| `status` | `discovery_status` | `ADMITTED_MATCH` / `PENDING_ADMISSION` / `UNPINNED_BLOCKED` |
| `matched_admission_id` | `source_record_id` | `ADMITTED_MATCH`일 때만 채워진다 |
| `occurrences[].file` | `declared_in` | 저장소 상대 경로 |

`discovery_status`는 `admission_status`가 아니다. `ADMITTED_MATCH`는 "이미 승인된 record와 일치한다"는
관찰일 뿐이며, 승인 자체는 언제나 `registry/oss-registry.json`이 권위를 가진다. `scan_status`가 `FAIL`인
발견 결과는 불완전하므로 심사 판단 근거로 사용할 수 없다.
