# frozen_string_literal: true
#
# ENSO: allow the Chatwoot agent dashboard to be embedded in an <iframe> by the
# ENSO CRM. Rails ships `X-Frame-Options: SAMEORIGIN` by default and Chatwoot
# exposes no toggle, so we strip it and set a CSP `frame-ancestors` allowlist
# instead. Gated on ENSO_FRAME_ANCESTORS (space-separated origins, e.g.
# "https://crm.enso.ro"). When unset, this is a no-op and core behaviour is kept.
class EnsoFrameEmbeddingMiddleware
  def initialize(app)
    @app = app
    @ancestors = ENV.fetch('ENSO_FRAME_ANCESTORS', '').to_s.strip
  end

  def call(env)
    status, headers, body = @app.call(env)
    if @ancestors.present?
      headers.delete('X-Frame-Options')
      directive = "frame-ancestors 'self' #{@ancestors}"
      existing = headers['Content-Security-Policy']
      headers['Content-Security-Policy'] = existing.present? ? "#{existing}; #{directive}" : directive
    end
    [status, headers, body]
  end
end

# Insert at the front so it runs last on the response and can override the
# X-Frame-Options header set deeper in the stack.
Rails.application.config.middleware.insert_before(0, EnsoFrameEmbeddingMiddleware)
