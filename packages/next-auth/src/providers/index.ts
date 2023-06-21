import type { OAuthConfig, OAuthProvider, OAuthProviderType } from "./oauth"

import type { EmailConfig, EmailProvider, EmailProviderType } from "./email"

import type {
  CredentialsConfig,
  CredentialsProvider,
  CredentialsProviderType,
} from "./credentials"

export * from "./oauth"
export * from "./email"
export * from "./credentials"
export * from "./password"

export type ProviderType = "oauth" | "email" | "credentials" | "password"

export interface CommonProviderOptions {
  id: string
  name: string
  type: ProviderType
  options?: Record<string, unknown>
}

export type Provider = OAuthConfig<any> | EmailConfig | CredentialsConfig

export type BuiltInProviders = Record<OAuthProviderType, OAuthProvider> &
  Record<CredentialsProviderType, CredentialsProvider> &
  Record<EmailProviderType, EmailProvider>

export type AppProviders = Array<
  Provider | ReturnType<BuiltInProviders[keyof BuiltInProviders]>
>

export interface AppProvider extends CommonProviderOptions {
  signinUrl: string
  callbackUrl: string
}

export type RedirectableProviderType = "email" | "credentials" | "password"

export type BuiltInProviderType = RedirectableProviderType | OAuthProviderType
