# TC-JARVIS Ledger Adapter Contract (P4)

`docs/JARVIS_LEDGER_INTEGRATION.md`가 *무엇을* 투영하는지 정한다면, 이 문서는 *어떻게* 투영하는지를
정한다. 스키마는 `schemas/jarvis-ledger-projection.schema.json`이다.

## 0. 원칙

**레저는 승인 시스템이 아니다.** adapter는 결과를 기록하고 전달할 뿐이며 `APPROVED`, `ADMITTED`,
`ledger_id`를 새로 만들지 않는다. 승인 권한은 `registry/oss-registry.json`과 사람의 심사에만 있다.

## 1. 확정된 결정

| # | 결정 |
| --- | --- |
| 1 | `source_commit`을 evidence 파일에 추가하지 않는다 |
| 2 | `source_commit`은 projection 생성 시 git HEAD에서 주입한다 |
| 3 | record 단위 validation을 추가하지 않는다 |
| 4 | 기존 aggregate PASS/FAIL을 그대로 전달한다 |
| 5 | registry의 `ledger_id`만 권위 있는 id로 전달한다 |
| 6 | `ledger_id`를 파생하거나 새로 생성하지 않는다 |
| 7 | discovery 후보는 `review_queue`로만 전달한다 |
| 8 | `review_queue` 항목에 `admission_status`·`ledger_id`를 만들지 않는다 |
| 9 | `errors`는 절대경로·자격증명·환경정보를 마스킹한다 |
| 10 | registry·evidence·discovery 결과 파일을 수정하지 않는다 |
| 11 | validator와 discovery는 `--check` 모드로만 호출한다 |
| 12 | remote adapter와 인증은 이번 범위 밖이다 |

결정 1·2가 함께 성립하는 이유: evidence는 **결정적 산출물**이고 projection은 **provenance 기록**이다.
커밋 SHA를 evidence에 넣으면 커밋마다 바이트가 달라져 `discover_dependencies.py --check`가 매번
실패한다. 실행 이력은 projection 쪽에만 남긴다.

## 2. 상태 어휘 분리

harness에는 어휘가 5개 있고, 서로 겹치는데 의미는 다르다. adapter는 이들을 **합치지 않고 각각 별도
필드로** 전달한다.

| harness 어휘 | 값 | 권위 | projection 필드 |
| --- | --- | --- | --- |
| registry `status` | PENDING / APPROVED / BLOCKED / REVOKED | 사람 심사 | `admitted_sources[].admission_status` |
| `jarvis_ledger.governance_status` | ADMITTED / PENDING / BLOCKED / REVOKED | registry 파생 | 전달하지 않음 (아래 참고) |
| discovery `status` | ADMITTED_MATCH / PENDING_ADMISSION / UNPINNED_BLOCKED | 기계 관찰 | `review_queue[].discovery_status` |
| validation `status` | PASS / FAIL | 검증기 | `registry_integrity` |
| discovery `scan_status` | OK / FAIL | 발견기 | `scan_integrity` |

**충돌 4건과 분리 방식**

| 충돌 | 분리 |
| --- | --- |
| `ADMITTED` ↔ `ADMITTED_MATCH` | 필드를 나눈다. `discovery_status: ADMITTED_MATCH`는 "승인 record와 일치한다"는 관찰이며 `admission_status`가 되지 않는다. 매핑하면 발견기가 승인을 만드는 것과 같다 |
| `PENDING` ↔ `PENDING_ADMISSION` | 전자는 "record가 있고 심사 대기", 후자는 "record가 없음"으로 정반대다. 서로 다른 배열에 담는다 |
| `BLOCKED` ↔ `UNPINNED_BLOCKED` | 사람 결정과 기계 판정을 구분한다 |
| `FAIL` (validation) ↔ `FAIL` (scan) | `registry_integrity`와 `scan_integrity`로 나눈다 |

`governance_status`를 전달하지 않는 이유: validator가 `status != APPROVED`인 record를 거부하고
`{"APPROVED": "ADMITTED"}`로만 매핑하므로, 유효한 레지스트리에서 이 값은 **항상 `ADMITTED`**다.
정보가 0이며, 전달하면 `ADMITTED_MATCH`와 혼동될 위험만 남는다.

## 3. 필드 매핑

### A. `admitted_sources` — registry 유래, 권위 있음

| registry | projection | 규칙 |
| --- | --- | --- |
| `jarvis_ledger.ledger_id` | `id` | **선언값 복사. 파생·생성 금지** |
| `admission_id` | `source_record_id` | 불변 |
| `component` | `component` | 그대로 |
| `source.source_url` | `source_url` | 그대로 |
| `source.immutable_ref` | `pinned_ref` | 그대로 |
| `license` | `license_expression` | SPDX |
| `status` | `admission_status` | 그대로 |
| `evidence_refs` | `evidence_refs` | 상대경로 유지 |

`ledger_id`는 현재 3개 record가 모두 `oss-X → oss.X` 규칙과 일치하지만 **파생하면 안 된다.**
파생 로직은 두 번째 진실 소스가 되고, 규칙이 어긋나는 record가 하나 생기는 순간 조용히 틀린다.

### B. `review_queue` — discovery 유래, 권위 없음

| discovery | projection | 규칙 |
| --- | --- | --- |
| `candidate_id` | `candidate_id` | 큐 내부 식별자. 레저 id로 승격 금지 |
| `status` | `discovery_status` | 그대로 |
| `component` | `component` | 그대로 |
| `source_url` | `source_url` | 그대로 |
| `immutable_ref` | `pinned_ref` | `null` 허용 |
| `matched_admission_id` | `source_record_id` | `ADMITTED_MATCH`일 때만, 아니면 `null` |
| `occurrences[].file` | `declared_in` | 정렬·중복 제거 |

`PENDING_ADMISSION`·`UNPINNED_BLOCKED` 후보는 `admission_id`가 없으므로 `id`가 **없다.**
id를 만들어내면 그 순간이 자동 등록이다.

## 4. `run_id`와 `source_commit`

```
run_id = sha256(source_commit ‖ sha256(canonical(validation)) ‖ sha256(canonical(discovery)))
```

`canonical(obj)`은 UTF-8, `sort_keys=True`, `separators=(",", ":")`로 직렬화한 JSON이다.
원문 바이트가 아니라 canonical JSON을 쓰는 이유는 두 가지다. `project()`가 순수 함수라 파일이
아니라 파싱된 객체를 받고, **의미가 같고 키 순서·공백만 다른 입력이 같은 `run_id`를 가져야**
하기 때문이다. 파일 경유와 테스트 경유가 동일한 값을 낸다.

`source_commit`은 두 evidence 어디에도 없으므로 adapter가 git HEAD에서 주입한다.
(`discovery-result`에 보이는 `commit_sha`는 `ref_kind` **값**이지 provenance가 아니다.)

**`run_id`는 중복 억제용이며 캐시 키가 아니다.** validation은 `reviewed_at + 180일` 만료를
`date.today()`로 판정하므로, 입력이 한 글자도 바뀌지 않아도 결과가 시간만으로 뒤집힌다
(현재 3개 record는 2027-02-27 만료). 같은 `run_id`를 근거로 재평가를 생략해서는 안 된다.

projection 본문에는 벽시계 시각을 넣지 않는다. 넣으면 projection 자체의 바이트 결정성이 깨진다.
수신 시각은 하위 레저가 기록한다.

## 5. PASS / FAIL / ERROR

harness는 소스별로 2상태만 낸다. 세 번째 상태는 **adapter 자신의 것**이다.

| `adapter_status` | 조건 | publish | 종료 코드 | 재시도 |
| --- | --- | --- | --- | --- |
| `PASS` | `registry_integrity: PASS` **그리고** `scan_integrity: OK` | 한다 | `0` | 불필요 |
| `FAIL` | 둘 중 하나라도 실패 — 판정은 됐고 결과가 나쁘다 | **한다** | `1` | **무의미.** 사람이 레지스트리·소스를 고쳐야 한다 |
| `ERROR` | 판정 불가 — 입력 누락·파싱 실패·adapter 예외 | **하지 않는다** | `2` | 가능 |

`FAIL`과 `ERROR`를 합치면 두 방향으로 틀린다. adapter 크래시가 거버넌스 실패로 보이거나,
거버넌스 실패가 재시도하면 낫는 일시 오류로 보인다.

`FAIL`을 publish하는 이유: 무엇이 잘못됐는지 **판정이 끝난 완전한 결과**이며, 레저는 실패 사실을
기록해야 한다. `ERROR`를 publish하지 않는 이유: 무엇이 참인지 판정하지 못한 상태라 신뢰할 수 있는
문서를 만들 수 없다. 이때 `registry_integrity`·`scan_integrity`는 `UNKNOWN`이며, 읽지 못한 값을
`PASS`나 `FAIL`로 단정하지 않는다.

## 6. 부분 결과 · 재시도

- **`ERROR`에서는 publish하지 않는다.** `PASS`와 `FAIL`은 완전한 판정이므로 publish한다.
- `scan_integrity: FAIL`이면 후보 목록이 불완전하다. `review_queue: []`를 "깨끗함"으로 읽어서는 안 된다.
  `review_queue`가 비어 있다는 사실은 `scan_integrity`와 **반드시 함께** 해석한다.
- 읽기는 순수하므로 재시도는 안전하다. 단 `FAIL`은 재시도로 `PASS`가 되지 않는다.

## 7. `errors` 마스킹

발견기의 오류 문자열은 대부분 저장소 상대경로라 안전하다. 다만 두 경로가 `{exc}`를 그대로 넣는다:

```
scan.error(f"registry: unreadable or malformed ({exc})")
scan.error(f"{rel}: malformed TOML ({exc})")
```

`OSError`는 `[Errno 13] Permission denied: '/절대/경로'` 형태로 전체 경로를 포함한다.
(`JSONDecodeError`·`TOMLDecodeError`는 경로를 담지 않아 안전하다.)

**마스킹 규칙 3개**

| # | 규칙 | 예 |
| --- | --- | --- |
| 1 | 절대경로 → basename만 | `/home/u/x/oss-registry.json` → `<oss-registry.json>` |
| 2 | URL userinfo 제거 | `https://u:tok@h/r` → `https://h/r` |
| 3 | 알려진 자격증명 접두사 → 치환 | `ghp_…` `ghs_…` `github_pat_…` `xox[baprs]-…` `AKIA…` → `<redacted>` |

`source_url`은 이미 안전하다. `normalize_source_url`이 userinfo·query·fragment를 모두 제거하는 것을
실측 확인했다 (`ghp_` `ghs_` `x-access-token` `token=` 전부 제거됨). 마스킹은 `errors`와,
manifest에서 원문 그대로 복사되는 `declared_ref`·`component`에 적용한다.

## 8. Adapter 인터페이스

```python
collect(root: Path)               -> RawEvidence   # I/O 경계
project(raw: RawEvidence, prov)   -> Projection    # 순수 함수, 부작용 없음
render(projection: Projection)    -> str           # 결정적 직렬화
emit(text: str, sink)                              # I/O 경계
main(argv) -> int                                  # PASS=0, FAIL=1, ERROR=2
```

`project()`가 유일한 정책 지점이며 **순수**하다. file adapter와 remote adapter는 `collect`/`emit`
구현만 다르고 `project()`를 공유한다. 정책이 두 벌로 갈라지지 않게 하는 것이 이 분리의 목적이다.

| | file adapter (P4) | remote adapter (범위 밖) |
| --- | --- | --- |
| 입력 | 로컬 checkout 3개 파일 | HTTP/API |
| 신뢰 | CI 게이트를 통과한 트리 | **미신뢰 입력** — 스키마 검증 필수 |
| provenance | 로컬 git HEAD | 응답이 commit SHA를 제공해야 함 |
| 인증 | 없음 | 필요 → 비밀값 취급이 새로 생김 |
| 방향 | 단방향 | 단방향 유지 (write-back 금지) |

## 9. 금지 (구현 시 하드 제약)

- registry·evidence 쓰기 금지
- `APPROVED`/`ADMITTED` **생성** 금지 — 읽어서 전달만
- 미승인 후보에 `id` 부여 금지
- `ledger_id` 파생 금지
- validator·discovery를 write 모드로 호출 금지 — `--check`만.
  인자 없이 `discover_dependencies.py`를 호출하면 evidence를 덮어쓴다
- validator `errors` 문자열을 파싱해 record별 상태를 만들지 말 것 —
  그 형식은 스키마로 고정돼 있지 않다
