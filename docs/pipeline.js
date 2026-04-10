flowchart LR
    %% =========================
    %% Styles
    %% =========================
    classDef source fill:#e8f5e9,stroke:#43a047,color:#1b1b1b,stroke-width:1px;
    classDef sfn fill:#eef3ff,stroke:#5c6bc0,color:#1b1b1b,stroke-width:1px;
    classDef decision fill:#fff8e1,stroke:#f9a825,color:#1b1b1b,stroke-width:1px;
    classDef ddb fill:#ede7f6,stroke:#7e57c2,color:#1b1b1b,stroke-width:1px;
    classDef s3 fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b,stroke-width:1px;
    classDef lambda fill:#fff3e0,stroke:#ef6c00,color:#1b1b1b,stroke-width:1px;
    classDef terminalGood fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b,stroke-width:1px;
    classDef terminalBad fill:#ffebee,stroke:#c62828,color:#1b1b1b,stroke-width:1px;
    classDef ai fill:#f3e5f5,stroke:#8e24aa,color:#1b1b1b,stroke-width:1px;

    %% =========================
    %% Event source
    %% =========================
    subgraph SRC["Event Source"]
        S3RAW["Amazon S3 delivery prefix<br/>s3://ingest-raw/&lt;project_code&gt;/&lt;asset_set&gt;/"]:::source
        MARKER["_INGEST_DONE uploaded<br/>ObjectCreated event"]:::source
        STARTER["ingest-on-done-create-job<br/>- parse folder scope<br/>- idempotency check<br/>- create job row<br/>- start Step Functions"]:::lambda
        S3RAW --> MARKER --> STARTER
    end

    %% =========================
    %% Orchestration
    %% =========================
    subgraph SFN["AWS Step Functions - Ingest Pipeline v1.1"]
        INIT["InitContext"]:::sfn
        ST_VALIDATING["UpdateJobState<br/>VALIDATING"]:::ddb
        VALIDATE["ValidateFiles<br/>- list S3 once<br/>- exclude marker<br/>- basic sanity checks<br/>- build inventory + stats"]:::lambda
        CHK_VALID{"validation ok?"}:::decision

        ST_FAILED_VALID["UpdateJobState<br/>FAILED_VALIDATION"]:::ddb

        ST_PREFLIGHT["UpdateJobState<br/>PREFLIGHT_VALIDATED"]:::ddb
        NORMALIZE["NormalizeValidateResult"]:::sfn
        MANIFEST["WriteManifest"]:::lambda
        ST_DEEP_VALIDATING["UpdateJobState<br/>DEEP_VALIDATING"]:::ddb

        DETECT_MHL["DetectMhlPresence"]:::lambda
        CHK_MHL{"MHL present?"}:::decision
        VERIFY_MHL["ChecksumVerifyMhl<br/>mode = VERIFY_MHL"]:::lambda
        BASELINE["ChecksumBaseline<br/>mode = BASELINE_ONLY"]:::lambda

        MEDIA["DeepValidateMedia<br/>ffprobe via layer"]:::lambda
        MEDIA_POLICY["DeepValidateMediaPolicy"]:::lambda
        BUILD_SUMMARY["BuildDeepValidationSummary"]:::sfn
        ST_DEEP_VALIDATED["UpdateJobState<br/>DEEP_VALIDATED"]:::ddb

        CHK_POLICY{"media policy ok?"}:::decision
        ST_REJECT["UpdateJobState<br/>REJECTED_POLICY"]:::ddb
        ST_REVIEW["UpdateJobState<br/>READY_FOR_REVIEW"]:::ddb

        ASSET_REJECT["WriteAssetReport<br/>(REJECTED_POLICY)"]:::lambda
        REPORT_REJECT["WriteReport<br/>(REJECTED_POLICY)"]:::lambda
        AI_REJECT["WriteAiReport<br/>(advisory)"]:::ai

        ASSET_REVIEW["WriteAssetReport<br/>(READY_FOR_REVIEW)"]:::lambda
        REPORT_REVIEW["WriteReport<br/>(READY_FOR_REVIEW)"]:::lambda
        AI_REVIEW["WriteAiReport<br/>(advisory)"]:::ai

        DONE["Done"]:::terminalGood

        INIT --> ST_VALIDATING --> VALIDATE --> CHK_VALID
        CHK_VALID -- "No" --> ST_FAILED_VALID --> DONE
        CHK_VALID -- "Yes" --> ST_PREFLIGHT --> NORMALIZE --> MANIFEST --> ST_DEEP_VALIDATING --> DETECT_MHL --> CHK_MHL

        CHK_MHL -- "Yes" --> VERIFY_MHL --> MEDIA
        CHK_MHL -- "No" --> BASELINE --> MEDIA

        MEDIA --> MEDIA_POLICY --> BUILD_SUMMARY --> ST_DEEP_VALIDATED --> CHK_POLICY

        CHK_POLICY -- "No" --> ST_REJECT --> ASSET_REJECT --> REPORT_REJECT --> AI_REJECT --> DONE
        CHK_POLICY -- "Yes" --> ST_REVIEW --> ASSET_REVIEW --> REPORT_REVIEW --> AI_REVIEW --> DONE
    end

    STARTER --> INIT

    %% =========================
    %% Artifact storage
    %% =========================
    subgraph ART["Artifacts / State"]
        DDB["DynamoDB<br/>IngestJobs<br/>authoritative job-state source of truth"]:::ddb

        MANI["manifest.json<br/>s3://.../&lt;project_code&gt;/_manifests/&lt;job_id&gt;.json"]:::s3
        ASSET_R["asset_report.json<br/>s3://.../&lt;project_code&gt;/_asset_reports/&lt;job_id&gt;.json"]:::s3
        REPORT_R["report.json<br/>s3://.../&lt;project_code&gt;/_reports/&lt;job_id&gt;.json"]:::s3
        AI_R["ai_report.json<br/>s3://.../&lt;project_code&gt;/_ai_reports/&lt;job_id&gt;.json"]:::s3
    end

    %% DDB writes
    STARTER -. create job row .-> DDB
    ST_VALIDATING -. state update .-> DDB
    ST_FAILED_VALID -. state update + validation_errors .-> DDB
    ST_PREFLIGHT -. state update .-> DDB
    MANIFEST -. persist manifest pointer .-> DDB
    ST_DEEP_VALIDATING -. state update + manifest_s3_uri .-> DDB
    ST_DEEP_VALIDATED -. state update + compact deep_validation_summary .-> DDB
    ST_REJECT -. state update + policy_reason .-> DDB
    ST_REVIEW -. state update .-> DDB

    %% S3 artifact writes
    MANIFEST --> MANI
    ASSET_REJECT --> ASSET_R
    ASSET_REVIEW --> ASSET_R
    REPORT_REJECT --> REPORT_R
    REPORT_REVIEW --> REPORT_R
    AI_REJECT --> AI_R
    AI_REVIEW --> AI_R

    %% AI inputs
    REPORT_R -. deterministic input .-> AI_REJECT
    ASSET_R -. deterministic input .-> AI_REJECT
    REPORT_R -. deterministic input .-> AI_REVIEW
    ASSET_R -. deterministic input .-> AI_REVIEW

    %% Notes
    NOTE1["Structural validation is the hard gate"]:::terminalGood
    NOTE2["Deep validation records findings;<br/>DEEP_VALIDATED means complete, not necessarily pass"]:::terminalGood
    NOTE3["AI report is advisory only;<br/>does not affect routing or job state"]:::terminalGood

    VALIDATE -.-> NOTE1
    ST_DEEP_VALIDATED -.-> NOTE2
    AI_REVIEW -.-> NOTE3