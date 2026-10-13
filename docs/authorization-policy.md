# Authorization policy

The bundled labs are synthetic programs intended for local execution by their
operator. They require no scanning, requests to a remote target, third-party
credentials, or access to another person's data.

When adapting Patchproof to another project, establish authorization before
reproducing a vulnerability. Record:

- The owner granting permission and the operator performing the work.
- The specific source revision, systems, environments, and data in scope.
- Permitted test methods, resource limits, and any approved time window.
- Stop conditions, reporting channel, and evidence retention requirements.

An open-source license or access to a public service does not by itself grant
permission to test somebody else's deployed system. Keep reproduction local
and use synthetic data where possible. Stop if testing reaches an unapproved
system or exposes unexpected sensitive data, and follow the agreed reporting
process.

Only execute fixtures whose code and manifests have been reviewed and trusted.
The runner enforces execution bounds, not authorization or containment. It has
no mechanism to verify ownership, block network access, or restrict filesystem
access. An operator must provide those controls when their environment requires
them.

Before sharing reports, review source excerpts, inputs, and outputs for secrets
and sensitive data. Do not publish another project's vulnerability details
outside its agreed disclosure process.

## Claude and CVP use

The initial proposed workflow is personal research on these synthetic local
fixtures. Preparing an offline prompt package is not a model invocation or CVP
authorization. A future Claude interaction must use an account the operator is
entitled to use, respect the applicable usage policy, and contain only material
the operator is permitted to share with the provider. Do not share credentials,
personal data, or identity documents through the research repository.

A CVP grant does not authorize testing any particular third-party system. It
also does not authorize a client-facing model product or service: the
[official program help article](https://support.claude.com/en/articles/14604842-cyber-verification-program)
requires separate application and approval for such use (accessed 2026-10-13,
Asia/Seoul). No customer-facing service, external scanning campaign, or access
sharing is part of this starter's proposed research scope.

Record authorization and disclosure terms before adapting the project to another
owner's code or infrastructure. Keep grant use within the approved scope and do
not treat reduced blocking as permission to exceed it.
