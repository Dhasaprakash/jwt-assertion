-- jwt-assertion plug-in is to verify the client assertion token or to generate the nexus assertion token to partners

local log = kong.log

local PLUGIN_NAME = "jwt-assertion"
local cache     = require "kong.plugins.jwt-assertion.cache"

local assertion_header_key = {
  type = "string",
  default = "x-jws-signature",
  required = true
}

-- leeway to verify the request signed time (iat) + leeway (expiry) in seconds
local leeway_config = {
  type = "integer",
  default = 60,
  required = true
}

-- clock_skew to adjust clock time with partner server time
local clock_skew_adj = {
  type = "integer",
  default = 60,
  required = true
}

local assertion_token_jwks_uri = {
  type = "string",
  required = false
}

local assertion_token_keyset = {
  type = "string",
  default = "nexus",
  required = false,
}

local algo_to_use = {
  type = "string",
  default = "RS256",
  required = true,
}

-- local strings_array = {
--   type = "array",
--   default = {},
--   required = true,
--   elements = { type = "string" }
-- }


local headers_array = {
  type = "array",
  default = {},
  required = true,
  elements = { type = "string"}
}

local request_uri = {
  type = "boolean",
  default = true,
  required = true
}

local http_method = {
  type = "boolean",
  default = true,
  required = true
}

local delimiter_config = {
  type = "string",
  default = "|",
  required = true
}

local hash_attribute = {
  type = "string",
  default = "payload_hash",
  required = true
}

local is_include_payload = {
  type = "boolean",
  default = true,
  required = true
}


-- local public_key_jwks to verify the jwt
-- local private_key to sign the jwt

local strings_array_record = {
  type = "record",
  fields = {
    { uri = request_uri },
    { headers = headers_array },
    { method = http_method },
    { payload = is_include_payload },
    { hash_claim = hash_attribute },
    { delimiter = delimiter_config },
  },
}

local ACTION = {
  "verify",
  "generate"
}

local action_config = {
  type = "string",
  required = true,
  one_of = ACTION
}

local get_phase = ngx.get_phase


local function validate_assertion_tokens(conf)
  log.info("Conf ",conf)
  local phase = get_phase()
  if phase == "access" or phase == "content" then
    log.info("Jwks enpoint ",conf.jwks_uri)
    local assertion_token_jwks_uri = conf.jwks_uri
    if assertion_token_jwks_uri then
      local ok, err = cache.load_keys(assertion_token_jwks_uri)
      if not ok then
        log.error("error in loading assertion token jwks (", err, ")")
        return false, "error in loading assertion token jwks"
      end
    end

    log.info("Jwk enpoint ",conf.keyset)
    local assertion_token_keyset = conf.keyset
    if assertion_token_keyset then
      local ok, err = cache.load_keys(assertion_token_keyset)
      if not ok then
        log.error("Error in loading assertion token keyset (", err, ")")
        return false, "Error in loading assertion token keyset"
      end
    end

    if assertion_token_keyset ~= "nexus" and assertion_token_keyset ~= "nexus" then
      local ok, err = cache.load_keys("nexus")
      if not ok then
        log.error("Error in loading assertion nexus keyset (", err, ")")
        return false, "Error in loading assertion nexus keyset"
      end
    end
  end

  return true
end

return {
  name = PLUGIN_NAME,
  fields = {
    { 
      config = {
        type = "record",
        custom_validator = validate_assertion_tokens,
        fields = {
          { assertion_header = assertion_header_key},
          { include  = strings_array_record },
          { action = action_config },
          { clock_skew = clock_skew_adj },
          { leeway = leeway_config },
          { algorithm = algo_to_use },
          { jwks_uri = assertion_token_jwks_uri },
          { keyset = assertion_token_keyset}
        }
      },
    },
  }
}
