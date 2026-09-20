# SecretGuard

SecretGuard verifies GitHub push webhooks, queues an asynchronous EventBridge
scan, fetches each pushed commit's diff from GitHub, and stores masked findings
in DynamoDB. A separate containment Lambda handles managed AWS keys, while a
notifier sends deterministic remediation guidance through SNS.

## Deploy

Create a fine-grained, read-only GitHub PAT scoped only to the private demo
repository, then create the config secret before deployment:

```bash
WEBHOOK_SECRET=$(openssl rand -hex 32)
aws secretsmanager create-secret --name secretguard/config \
  --secret-string "{\"github_token\":\"github_pat_XXXX\",\"webhook_secret\":\"$WEBHOOK_SECRET\"}"
```

Pass that secret ARN to `SecretGuardConfigArn` during `sam deploy --guided`.
Set `AlertEmail` and click the SNS confirmation link. Set `ProtectedUsers` to
comma-separated IAM usernames that must never be disabled.

```bash
sam build
sam deploy --guided
```

Configure the GitHub webhook with the stack's `WebhookUrl`, content type
`application/json`, the same webhook secret, and the `push` event. Subscribe an
operator to the `RemediationTopicArn` output to receive type-specific guidance.

For containment, use a throwaway IAM user under the
`/secretguard-managed/` path with zero permissions. SecretGuard looks up
the access-key owner using `GetAccessKeyLastUsed`, disables only allowed
managed users, and treats unknown keys as not ours. It never stores or emits
an AWS secret access key; AWS access-key IDs are retained only as identifiers,
while all secret values are masked.

Use a private repository and fake credential-like values for the initial scan
demo. For the containment demo only, use a disposable test identity; never
use a personal or root AWS credential.

For the containment test, create a disposable zero-permission user:

```bash
aws iam create-user --user-name demo-leaked-user --path /secretguard-managed/
aws iam create-access-key --user-name demo-leaked-user
```

The expected finding includes `AWS_ACCESS_KEY`, a fully masked secret value,
the safe access-key ID, `status: CONTAINED`, and `seconds_to_contain`.

Known limits: detection happens after a push; regex rules can have false
positives and misses; binary and very large files may have no GitHub patch;
temporary `ASIA...` keys and keys owned by another account are reported but not
disabled; CloudTrail lookup is a follow-up because it is not immediate.
