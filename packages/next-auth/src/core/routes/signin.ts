import getAuthorizationUrl from "../lib/oauth/authorization-url"
import emailSignin from "../lib/email/signin"
import getAdapterUserFromEmail from "../lib/email/getUserFromEmail"
import type { RequestInternal, ResponseInternal } from ".."
import type { InternalOptions } from "../types"
import type { Account } from "../.."
import password from "../lib/password/signin"
import type { User } from "../.."
import { EmailNotVerified } from "../errors"
import { PasswordRecord } from "src/providers/password"

/** Handle requests to /api/auth/signin */
export default async function signin(params: {
  options: InternalOptions<"oauth" | "email" | "password">
  query: RequestInternal["query"]
  body: RequestInternal["body"]
}): Promise<ResponseInternal> {
  const { options, query, body } = params
  const { url, callbacks, logger, provider } = options

  if (!provider.type) {
    return {
      status: 500,
      // @ts-expect-error
      text: `Error: Type not specified for ${provider.name}`,
    }
  }

  if (provider.type === "oauth") {
    try {
      const response = await getAuthorizationUrl({ options, query })
      return response
    } catch (error) {
      logger.error("SIGNIN_OAUTH_ERROR", {
        error: error as Error,
        providerId: provider.id,
      })
      return { redirect: `${url}/error?error=OAuthSignin` }
    }
  } else if (provider.type === "email") {
    let email: string = body?.email
    if (!email) return { redirect: `${url}/error?error=EmailSignin` }
    const normalizer: (identifier: string) => string =
      provider.normalizeIdentifier ??
      ((identifier) => {
        // Get the first two elements only,
        // separated by `@` from user input.
        let [local, domain] = identifier.toLowerCase().trim().split("@")
        // The part before "@" can contain a ","
        // but we remove it on the domain part
        domain = domain.split(",")[0]
        return `${local}@${domain}`
      })

    try {
      email = normalizer(body?.email)
    } catch (error) {
      logger.error("SIGNIN_EMAIL_ERROR", { error, providerId: provider.id })
      return { redirect: `${url}/error?error=EmailSignin` }
    }

    const user = await getAdapterUserFromEmail({
      email,
      // @ts-expect-error -- Verified in `assertConfig`. adapter: Adapter<true>
      adapter: options.adapter,
    })

    const account: Account = {
      providerAccountId: email,
      userId: email,
      type: "email",
      provider: provider.id,
    }

    // Check if user is allowed to sign in
    try {
      const signInCallbackResponse = await callbacks.signIn({
        user,
        account,
        email: { verificationRequest: true },
      })
      if (!signInCallbackResponse) {
        return { redirect: `${url}/error?error=AccessDenied` }
      } else if (typeof signInCallbackResponse === "string") {
        return { redirect: signInCallbackResponse }
      }
    } catch (error) {
      return {
        redirect: `${url}/error?${new URLSearchParams({
          error: error as string,
        })}`,
      }
    }

    try {
      const redirect = await emailSignin(email, options)
      return { redirect }
    } catch (error) {
      logger.error("SIGNIN_EMAIL_ERROR", { error, providerId: provider.id })
      return { redirect: `${url}/error?error=EmailSignin` }
    }
  } else if (provider.type === "password") {
    const credentials = body
    let email: string = body?.email

    if (!provider.authorize) {
      return { redirect: `${url}/error?error=configuration` }
    }

    let user: User | null = null
    try {
      user = await provider.authorize(
        credentials,
        {
          query,
          body,
        },
        options
      )
      if (!user) {
        return {
          status: 401,
          redirect: `${url}/error?${new URLSearchParams({
            error: "PasswordSignin",
            provider: provider.id,
          })}`,
        }
      }
    } catch (error) {
      if (!(error instanceof EmailNotVerified)) {
        return {
          status: 401,
          redirect: `${url}/error?error=${encodeURIComponent(
            (error as Error).message
          )}`,
        }
      }
    }

    const credentialKeys = Object.keys(provider.credentials)
    const requireEmailVerification =
      provider.emailVerificationEnabled &&
      provider.emailVerificationRequired &&
      credentialKeys.includes("email")

    if (requireEmailVerification) {
      if (!email) return { redirect: `${url}/error?error=VerifyEmailAddress` }

      if (!user) {
        // email address not verified
        try {
          const redirect = await password(email, options)
          return { redirect }
        } catch (error) {
          logger.error("SIGNIN_EMAIL_VERIFICATION_ERROR", {
            error,
            providerId: provider.id,
          })
          return { redirect: `${url}/error?error=VerifyEmailAddress` }
        }
      }
    }

    if (!user) {
      return { redirect: `${url}/error?error=AccessDenied` }
    }

    const normalizer: (identifier: string) => string =
      provider.normalizeIdentifier ??
      ((identifier) => {
        // Get the first two elements only,
        // separated by `@` from user input.
        let [local, domain] = identifier.toLowerCase().trim().split("@")
        // The part before "@" can contain a ","
        // but we remove it on the domain part
        domain = domain.split(",")[0]
        return `${local}@${domain}`
      })

    try {
      email = normalizer(body?.email)
    } catch (error) {
      logger.error("SIGNIN_PASSWORD_EMAIL_ERROR", {
        error,
        providerId: provider.id,
      })
      return { redirect: `${url}/error?error=VerifyEmailAddress` }
    }

    const providerAccountIdField = provider.identifier
    const account: Account = {
      providerAccountId: user[providerAccountIdField],
      type: "password" as const,
      provider: provider.id,
    }

    // Check if user is allowed to sign in
    try {
      const signInCallbackResponse = await callbacks.signIn({
        user,
        account,
        password: credentials as PasswordRecord,
      })
      if (!signInCallbackResponse) {
        return { redirect: `${url}/error?error=AccessDenied` }
      } else if (typeof signInCallbackResponse === "string") {
        return { redirect: signInCallbackResponse }
      }
    } catch (error) {
      return {
        redirect: `${url}/error?${new URLSearchParams({
          error: error as string,
        })}`,
      }
    }
  }

  return { redirect: `${url}/signin` }
}
