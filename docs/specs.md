# Invite service

go-invite-op is an invite code service

- Provides management of invite codes cleanly separated from other parts of SIROS ID
- Provides an OpenID OP interface compatible with the OpenID gate in go-wallet-backend and wallet-frontend
- Provides tenant-separation
- Provides an API that is protected with a tenant-scoped JWT 

The data-model is tenant-scoped. Each tenant is cleanly separated from every other tenant. Tenants are auto-created when referenced in an API call.

Each tenant maintains a list of "invites" with the following information:

1. An allowed email (foo@xample.com) or email-domain (@example.com)
2. An associated invite code that has an expiration (can be 0 for never expires) and can be limited to one use or can be used multiple times (or infinite).

The invite code is either generated (if absent in the API) when the email/domain entry is created and returned to the caller in the API response or provided by the caller along with other metadata.

If created by the service, invite code is generated using a cryptograpic random number generator.

The API permits creation, update and removal of invites.

The OP presents a simple UX: the user is prompted to input an email address after which the most specific invite entry (email over domain is preferred) is matched and used. The associated code is sent to the user with an email and the user is prompted to input the code in the OP as confirmation. Successful completion of this process results in a successful authentication response to the RP.

The use-count on an invite is updated upon successful confirmation.

The OP supports dynamic client registration.

Invite codes that are consumed (no remaining use count) or expired are periodically removed from the database.

Datastore is abstracted and supports both memory (for testing) and mongodb for production.

Use other repos in this workspace as a template for golang scaffolding. You are aiming for a high degree of alignment with other golang projects in the workspace.

In addition to JWT-based auth the API supports admin-tokens in line with what go-wallet-backend uses for the admin server.
