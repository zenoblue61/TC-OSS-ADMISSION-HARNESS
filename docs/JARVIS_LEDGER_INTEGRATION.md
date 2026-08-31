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
