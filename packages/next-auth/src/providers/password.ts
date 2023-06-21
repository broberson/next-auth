import { createTransport } from "nodemailer"

import type { RequestInternal } from "../core"
import type { CommonProviderOptions } from "."
import type { InternalOptions } from "../core/types"
import type { Options as SMTPTransportOptions } from "nodemailer/lib/smtp-transport"
import type { User, Awaitable } from ".."
import type { Theme } from "../core/types"
import { AdapterUser } from "src/adapters"
import { EmailNotVerified } from "src/core/errors"

const BCRYPT_ROUNDS = 12

export interface SendPasswordVerificationRequestParams {
  identifier: string
  url: string
  expires: Date
  provider: PasswordConfig
  token: string
  theme: Theme
}

export interface PasswordInput {
  label?: string
  type?: string
  value?: string
  placeholder?: string
}

export interface PasswordRecord extends Record<string, PasswordInput> {
  password: PasswordInput
}

export interface PasswordConfig<C extends PasswordRecord = PasswordRecord>
  extends CommonProviderOptions {
  type: "password"
  /**
   * Define the credentials fields you require for users to sign in. This
   * configuration must include an entry named `password`. To use email
   * verification (which is enabled by default) you must also include a
   * field named `email`.
   */
  credentials: C
  /**
   * The field in credentials that uniquely identifies a user, perhaps a
   * username or email address. This will be used as the ProviderAccountID
   * in the Accounts table.
   * @default "email"
   */
  identifier: keyof C
  /**
   * Send verification emails when a new user is created. To use this, you
   * must include an `email` field in the credentials you define.
   * @default true
   */
  emailVerificationEnabled: boolean
  /**
   * Email verification is required in order for a user to sign in
   * @default true
   */
  emailVerificationRequired: boolean
  // TODO: Make use of https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html
  server: string | SMTPTransportOptions
  /** @default "NextAuth <no-reply@example.com>" */
  from?: string
  /** [Documentation](https://next-auth.js.org/providers/email#customizing-emails) */
  sendVerificationRequest: (
    params: SendPasswordVerificationRequestParams
  ) => Awaitable<void>
  /**
   * How long until the e-mail can be used to verify the user's email address,
   * in seconds. Defaults to 1 day
   * @default 86400
   */
  maxAge?: number
  /**
   * By default, we are generating a random verification token.
   * You can make it predictable or modify it as you like with this method.
   * @example
   * ```js
   *  Providers.Email({
   *    async generateVerificationToken() {
   *      return "ABC123"
   *    }
   *  })
   * ```
   * [Documentation](https://next-auth.js.org/providers/email#customizing-the-verification-token)
   */
  generateVerificationToken?: () => Awaitable<string>
  /** If defined, it is used to hash the verification token when saving to the database . */
  secret?: string
  /**
   * Normalizes the user input before sending the verification request.
   *
   * ⚠️ Always make sure this method returns a single email address.
   *
   * @note Technically, the part of the email address local mailbox element
   * (everything before the `@` symbol) should be treated as 'case sensitive'
   * according to RFC 2821, but in practice this causes more problems than
   * it solves, e.g.: when looking up users by e-mail from databases.
   * By default, we treat email addresses as all lower case,
   * but you can override this function to change this behavior.
   *
   * [Documentation](https://next-auth.js.org/providers/email#normalizing-the-e-mail-address) | [RFC 2821](https://tools.ietf.org/html/rfc2821) | [Email syntax](https://en.wikipedia.org/wiki/Email_address#Syntax)
   */
  normalizeIdentifier?: (identifier: string) => string
  authorize?: (
    credentials: Record<keyof C, string> | undefined,
    req: Pick<RequestInternal, "body" | "query" | "headers" | "method">,
    options: InternalOptions<PasswordProviderType>
  ) => Awaitable<User | null>
  hash?: (text: string) => Awaitable<string>
  compare?: (text: string, hash: string) => Awaitable<boolean>
}

export type PasswordUserConfig<C extends PasswordRecord> = Partial<
  Omit<PasswordConfig<C>, "options">
> &
  Pick<
    PasswordConfig<C>,
    | "authorize"
    | "credentials"
    | "identifier"
    | "server"
    | "from"
    | "sendVerificationRequest"
    | "maxAge"
    | "generateVerificationToken"
    | "secret"
    | "normalizeIdentifier"
    | "hash"
    | "compare"
  >

export type PasswordProvider = <C extends PasswordRecord>(
  options: Partial<PasswordConfig<C>>
) => PasswordConfig<C>

export type PasswordProviderType = "password"

export interface PasswordAdapterUser extends AdapterUser {
  passwordHash: string
}

export default function Password<C extends PasswordRecord = PasswordRecord>(
  options: PasswordUserConfig<C>
): PasswordConfig<C> {
  return {
    id: "password",
    name: "Password",
    type: "password",
    credentials: {
      email: { label: "email", type: "text " },
      password: { label: "password", type: "password " },
    } as any,
    identifier: "email",
    emailVerificationEnabled: true,
    emailVerificationRequired: true,
    server: { host: "localhost", port: 25, auth: { user: "", pass: "" } },
    from: "NextAuth <no-reply@example.com>",
    maxAge: 24 * 60 * 60,
    authorize: async (credentials, req, options) => {
      const { adapter, logger, provider } = options
      const { getUserByAccount } = adapter
      const {
        identifier,
        hash,
        compare,
        emailVerificationEnabled,
        emailVerificationRequired,
      } = provider

      // ensure expected configuration requirements
      if (!provider.options) {
        throw new Error(
          "Provider options not available. Please report this as a bug."
        )
      }
      if (!hash || !compare) {
        throw new Error(
          "Missing hash/compare functions in Password provider configuration."
        )
      }

      // ensure that credentials of some kind were actually given
      if (!credentials) {
        throw new Error("Sign in credentials not provided.")
      }

      // ensure that all credentials were provided
      const credentialKeys = Object.keys(provider.credentials)
      let missingKeys: string[] = []
      for (const key in credentialKeys) {
        const value = credentials[key]
        if (typeof value === "undefined") {
          missingKeys.push(key)
        }
      }
      if (missingKeys.length) {
        let msg: string = ""
        if (missingKeys.length > 1) {
          const lastKey = missingKeys.pop()
          msg = `${missingKeys.join(", ")} and ${lastKey}`
        } else {
          msg = missingKeys[0]
        }
        throw new Error(`${msg} must be provided.`)
      }

      const requireEmailVerification =
        emailVerificationEnabled &&
        emailVerificationRequired &&
        credentialKeys.includes("email")

      // look up user by account id which will be the
      // credential field indicated by `identifier`
      const providerAccountId = credentials[identifier]
      const user = (await getUserByAccount({
        providerAccountId: providerAccountId,
        provider: provider.id,
      })) as PasswordAdapterUser

      // if no user was found, return null
      if (!user) {
        return null
      }

      // validate user's password
      const passwordHash = await hash(credentials.password)
      if (passwordHash != user.passwordHash) {
        return null
      }

      // if necessary, ensure that user's email address has been
      // validated already
      if (requireEmailVerification && !user.emailVerified) {
        throw new EmailNotVerified("Email address not verified")
      }

      return user
    },
    async sendVerificationRequest(params) {
      const { identifier, url, provider, theme } = params
      const { host } = new URL(url)
      const transport = createTransport(provider.server)
      const result = await transport.sendMail({
        to: identifier,
        from: provider.from,
        subject: `Please verify your email address.`,
        text: text({ url, host }),
        html: html({ url, host, theme }),
      })
      const failed = result.rejected.concat(result.pending).filter(Boolean)
      if (failed.length) {
        throw new Error(`Email (${failed.join(", ")}) could not be sent`)
      }
    },
    async hash(text) {
      const bcrypt = require("bcrypt")
      if (!bcrypt) {
        throw new Error(
          'bcrypt is required by the default password hashing function. Either install it with "npm install bcrypt" or provide your own hash and compare functions.'
        )
      }
      return await bcrypt.hash(text, BCRYPT_ROUNDS)
    },
    async compare(text, hash) {
      const bcrypt = require("bcrypt")
      if (!bcrypt) {
        throw new Error(
          'bcrypt is required by the default password hash compare function. Either install it with "npm install bcrypt" or provide your own hash and compare functions.'
        )
      }
      return await bcrypt.compare(text, hash)
    },
    options,
  }
}

/**
 * Email HTML body
 * Insert invisible space into domains from being turned into a hyperlink by email
 * clients like Outlook and Apple mail, as this is confusing because it seems
 * like they are supposed to click on it to sign in.
 *
 * @note We don't add the email address to avoid needing to escape it, if you do, remember to sanitize it!
 */
function html(params: { url: string; host: string; theme: Theme }) {
  const { url, host, theme } = params

  const escapedHost = host.replace(/\./g, "&#8203;.")

  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const brandColor = theme.brandColor || "#346df1"
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const buttonText = theme.buttonText || "#fff"

  const color = {
    background: "#f9f9f9",
    text: "#444",
    mainBackground: "#fff",
    buttonBackground: brandColor,
    buttonBorder: brandColor,
    buttonText,
  }

  return `
<body style="background: ${color.background};">
  <table width="100%" border="0" cellspacing="20" cellpadding="0"
    style="background: ${color.mainBackground}; max-width: 600px; margin: auto; border-radius: 10px;">
    <tr>
      <td align="center"
        style="padding: 10px 0px; font-size: 22px; font-family: Helvetica, Arial, sans-serif; color: ${color.text};">
        Activate your account at <strong>${escapedHost}</strong>
      </td>
    </tr>
    <tr>
      <td align="center" style="padding: 20px 0;">
        <table border="0" cellspacing="0" cellpadding="0">
          <tr>
            <td align="center" style="border-radius: 5px;" bgcolor="${color.buttonBackground}"><a href="${url}"
                target="_blank"
                style="font-size: 18px; font-family: Helvetica, Arial, sans-serif; color: ${color.buttonText}; text-decoration: none; border-radius: 5px; padding: 10px 20px; border: 1px solid ${color.buttonBorder}; display: inline-block; font-weight: bold;">Activate
                Account</a></td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td align="center"
        style="padding: 0px 0px 10px 0px; font-size: 16px; line-height: 22px; font-family: Helvetica, Arial, sans-serif; color: ${color.text};">
        If you did not request this email you can safely ignore it.
      </td>
    </tr>
  </table>
</body>
`
}

/** Email Text body (fallback for email clients that don't render HTML, e.g. feature phones) */
function text({ url, host }: { url: string; host: string }) {
  return `Activate your account at ${host}\n${url}\n\n`
}
