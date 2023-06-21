import { Theme } from "../.."
import { InternalUrl } from "../../utils/parse-url"

interface VerifyEmailPageProps {
  url: InternalUrl
  theme: Theme
}

export default function VerifyEmailPage(props: VerifyEmailPageProps) {
  const { url, theme } = props

  return (
    <div className="verify-request">
      {theme.brandColor && (
        <style
          dangerouslySetInnerHTML={{
            __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `,
          }}
        />
      )}
      <div className="card">
        {theme.logo && <img src={theme.logo} alt="Logo" className="logo" />}
        <h1>Check your email</h1>
        <p>A verification link has been sent to your email address.</p>
        <p>
          <a className="site" href={url.origin}>
            {url.host}
          </a>
        </p>
      </div>
    </div>
  )
}
