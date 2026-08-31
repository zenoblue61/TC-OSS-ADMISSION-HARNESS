# TC-OSS-ADMISSION-HARNESS

외부 오픈소스·GitHub 소스를 제품에 반입하기 전에 **특정 소스·특정 불변 버전·특정 사용 목적**을 승인하고 CI에서 검증하는 공급망 거버넌스 Harness입니다.

## 안전 모델

- `registry/oss-registry.json`에 없는 외부 소스는 허용하지 않습니다.
- 승인 단위는 패키지 이름이 아닌 `source_url + immutable_ref`입니다.
- `immutable_ref`는 Git commit SHA(40자리) 또는 정확한 버전 고정이어야 합니다.
- `APPROVED` 항목만 통과합니다. `PENDING`, `BLOCKED`, `REVOKED`는 CI를 실패시킵니다.
- 라이선스, 사용 목적, 소유자, 검토일, 증거 파일을 빠뜨릴 수 없습니다.

## 실행

```bash
python3 scripts/validate_admissions.py          # 레지스트리 검증 (P0~P2)
python3 scripts/discover_dependencies.py        # 의존성 발견 (P3)
python3 -m unittest discover -s tests -v
```

검증기와 발견기는 표준 라이브러리만 사용합니다. 소스 코드·lockfile을 자동 설치하거나 변경하지 않습니다.

## 의존성 발견 (P3)

`scripts/discover_dependencies.py`는 대상 트리를 **읽기 전용**으로 스캔하여 외부 소스 후보를 찾고
`evidence/discovery-result.json`에 증거를 남깁니다. 네트워크에 접근하지 않고, 무엇도 설치하지 않으며,
manifest·lockfile·레지스트리를 수정하지 않습니다.

### 스캔 대상

| 입력 | 추출 대상 |
| --- | --- |
| `package.json` | `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies` |
| `package-lock.json` | lockfile v1 `dependencies`, v2/v3 `packages` (`resolved`, `integrity` 포함) |
| `requirements*.txt` | PEP 508 요구사항, `-e`/`-r` 포함, 환경 마커·`--hash` 제거 |
| `pyproject.toml` | PEP 621 `project`, `build-system.requires`, PEP 735 `dependency-groups`, `tool.poetry.*` |
| `.github/workflows/*.yml`, `action.yml` | `uses:` (GitHub Action, 재사용 워크플로, `docker://`) |
| `vendored-sources.json` | vendored git source 선언 |

`file:`, `link:`, `workspace:`, `./` 등 저장소 내부 참조는 외부 소스가 아니므로 제외합니다.

### 판정

발견기는 후보를 **세 가지 상태로만** 분류합니다. `APPROVED`는 절대 생성하지 않습니다.

| 상태 | 조건 |
| --- | --- |
| `ADMITTED_MATCH` | 불변 ref로 고정되어 있고, `source_url + immutable_ref`가 registry의 **`APPROVED`** record와 일치 |
| `PENDING_ADMISSION` | 불변 ref로 고정되어 있으나 registry에 없거나, ref가 다르거나, record가 `APPROVED`가 아님 |
| `UNPINNED_BLOCKED` | 버전 범위·branch·tag·`latest`·무제약 등 고정되지 않은 ref |

불변으로 인정하는 ref는 `commit_sha`(40자리 SHA), `exact_version`(정확한 버전), `digest`뿐입니다.
고정되지 않은 후보는 registry와 대조하기 **전에** 차단되므로, 범위 표기가 승인과 일치하는 일은 없습니다.

### 매칭 정규화

매칭은 오직 `source_url`과 `immutable_ref` 두 필드로만 수행합니다. 표기 차이를 흡수하기 위해 양쪽에
동일한 정규화를 적용합니다.

- URL: `git+` 접두사·`.git` 접미사·후행 슬래시·쿼리·프래그먼트 제거, 호스트 소문자화,
  `git@host:path`·`github:owner/repo` 표기를 `https://host/path`로 통일
- ref: SHA·digest는 소문자화, 버전은 선행 `v`/`=` 제거 (`v1.2.3` = `1.2.3`)

레지스트리에 기록할 정규 URL 형식은 다음과 같습니다.

| 생태계 | `source_url` |
| --- | --- |
| npm | `https://registry.npmjs.org/<package>` |
| PyPI | `https://pypi.org/project/<pep503-normalized-name>` |
| GitHub Action | `https://github.com/<owner>/<repo>` |
| git / vendored | `https://<host>/<owner>/<repo>` |

### 재현성

출력은 타임스탬프와 절대 경로를 포함하지 않으며, 후보는
`(ecosystem, component, source_url, declared_ref)` 순으로, 발생 위치는 `(file, locator)` 순으로
정렬됩니다. 따라서 파일 시스템 순서나 스캔 경로와 무관하게 항상 동일한 바이트를 생성합니다.

### fail-closed

입력이 없거나 손상된 경우 `scan_status`는 `FAIL`이 되고 종료 코드는 1입니다. 손상된 JSON/TOML,
읽을 수 없는 파일, 존재하지 않는 `-r` 포함 대상, 누락·손상된 레지스트리가 이에 해당합니다.
레지스트리를 읽을 수 없으면 어떤 후보도 `ADMITTED_MATCH`가 될 수 없습니다.

### 옵션

```bash
python3 scripts/discover_dependencies.py --root <path> --registry <path> --output <path>
python3 scripts/discover_dependencies.py --check    # 커밋된 증거와 비교, 쓰기 없음 (CI에서 사용)
python3 scripts/discover_dependencies.py --strict   # 미승인 후보가 하나라도 있으면 종료 코드 1
python3 scripts/discover_dependencies.py --exclude <prefix>
```

CI는 `--check`만 사용합니다. 발견 자체는 게이트가 아니라 증거 생성이며, 승인 여부는 P0~P2
validator와 사람의 심사가 결정합니다. 소비 저장소에서 미승인 의존성 유입을 차단하려면
`--strict`를 사용하십시오.

현재 이 저장소는 자기 자신에게 정책을 적용하고 있습니다. 워크플로의 action은 commit SHA로
고정되어 있고 registry에 승인 record가 있으므로 발견 결과는 `unpinned_blocked: 0`,
`pending_admission: 0`이며 `--strict`도 종료 코드 0으로 통과합니다.

### GitHub Action 고정 절차

`OSS_ADMISSION_POLICY.md` 규칙 2에 따라 action은 태그가 아닌 commit SHA로 고정합니다.

```bash
git ls-remote --tags --refs https://github.com/<owner>/<repo> | grep 'refs/tags/<tag>$'
```

1. 위 명령으로 태그가 가리키는 commit SHA를 확인한다. 주석 태그(annotated tag)면
   `refs/tags/<tag>^{}`의 값이 commit SHA다.
2. 워크플로를 `uses: <owner>/<repo>@<40자리 SHA> # <release tag>`로 고정한다.
   태그는 이동 가능하므로 주석으로만 남기고, 대조 기준은 SHA다.
3. `registry/oss-registry.json`에 승인 record를, `evidence/`에 라이선스와 ref 출처를 담은
   evidence 파일을 추가한다.
4. `python3 scripts/discover_dependencies.py`로 발견 증거를 재생성한다.
5. `validate_admissions.py` PASS와 `discover_dependencies.py --check` PASS를 확인한다.

태그는 이동할 수 있으므로 SHA를 바꾸는 것은 새로운 심사 대상입니다. 자동 갱신하지 않습니다.

## TC-JARVIS 연결

각 승인 record의 `jarvis_ledger`는 TC-JARVIS master ledger에서 추적할 식별자와 상태를 담습니다. CI 결과는 `evidence/validation-result.json`에 생성하며, 이 파일을 상위 레저의 evidence reference로 연결할 수 있습니다. 발견 결과 `evidence/discovery-result.json`은 아직 승인되지 않은 유입 후보의 증거로 함께 연결합니다.

## 범위

- **P0~P2**: admission contract, 레지스트리/정책 검증, GitHub Actions gate.
- **P3**: 읽기 전용 의존성 발견과 PENDING 후보 증거 생성.

CVE 데이터베이스 연동, 자동 의존성 업데이트, 자동 승인, transitive 의존성 해석은 의도적으로 범위 밖입니다. 발견기는 선언된(declared) 의존성만 읽으며, 의존성 그래프를 해석하지 않습니다.
