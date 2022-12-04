
---------------------------------------------------------------------------------------------
-- jwt-assertion kong plugin
-- to genertate the verify the assertion token and generate assertion token for outgoing requests
-- {
--  "name" : "jwt-assertion",
--  "config" : {
--      "include" : {
--        "headers" : ["x-client-id","x-partner_id"]
--      },
--      "action" : "verify",
--      "jwks_uri" : "http://host.docker.internal:8080/access-management/.well-known/jwks.json", 
--      "keyset" : "nexus"
--  }
--}
-- specify the headers to be included as per contract with client/server to generate the hash
-- mentiontion action, either to verify or sign 
-- define jwks_uri to retrive client's public key and verify the assetion token using the public key
-- define keyset - private key to sign the hash of request payload as per config
---------------------------------------------------------------------------------------------
local sha256 = require "resty.sha256"
local log = kong.log
local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64
local jws =  require "kong.openid-connect.jws"
local cache = require "kong.plugins.jwt-assertion.cache"

local error = {}


local JWTAssertionHandler = {
  PRIORITY = 1000, 
  VERSION = "0.1"
}

local CHAR_TO_HEX = {};
for i = 0, 255 do
  local char = string.char(i)
  local hex = string.format("%02x", i)
  CHAR_TO_HEX[char] = hex
end

-- convert hash to hex string
local function hex_encode(str)
  return (str:gsub(".", CHAR_TO_HEX))
end


function JWTAssertionHandler:init_worker()
  log.debug("from jwt-assertion 'init_worker' handler")
  cache.init_worker()
end 


-- local function validate(conf)
--   -- string.sub(conf.delimiter,1,6)
--   return false
-- end

local function throw_expection(status, code, desc) 
  error.code = code
  error.desc = desc
  log.info("throw error ", error.code, error.desc)
  return kong.response.exit(status, {error})
end

local function validate_body()
  local kong_request = kong.request
  local body, err = kong_request.get_raw_body()
  local method = kong_request.get_method()

  if err then
    kong.log.debug(err)
    return false
  end
  if body == nil or body == "" then
    throw_expection(401, "PL00001", "Payload not found")
  end
  return true
end

local function generate_assertion_hash(message)
  log.info("message to hash ", message)
  local digest = sha256:new()
  digest:update(message or '')
  local generated_digest = hex_encode(digest:final())
  log.info("hash value ",generated_digest)
  return digest_created 
end

local function load_keys(...)
  return cache.load_keys(...)
end

local function verify_assertion_token(conf, generated_hash)
  if not assertion_token then
    -- throw_expection(401, "AT00001", "Assertion token not found")
  end
  local kong_request = kong.request
  local assertion_token = kong_request.get_header("x-jws-signature")
  log.info("jwks from conf", conf.jwks_uri)
  local jwks_uri = conf.jwks_uri
  local private_key, err = load_keys(conf.keyset)
  log.info("keyset keys ", private_key)
  local public_jwks, decoded_token, err
  if jwks_uri then
    public_jwks, err = load_keys(jwks_uri)
    log.info("public jwks from cache ", public_jwks)
    if not public_jwks then
      log.warn("jwks not loaded - error ")
      -- throw_expection(401, "AST00002", "Unauthorized")
    end
    decoded_token, err = jws.decode(assertion_token, {
      verify_signature = true,
      keys = public_jwks
    })
    if type(decoded_token) ~= "table" then
      log.warn("error in decode/verify assertion token")
      -- throw_expection(401, "AST00003", "Unauthorized")
    else
      local payload = decoded_token.payload
      local request_hash = payload.hash
      log.info("assertion Token claim hash",payload.hash)
      if request_hash == generated_hash then
        return true
      else 
        log.warn("hash mismatch error")
        -- throw_expection(403, "AST00004", "Forbidden")
      end
    end
  else 
    log.warn("invalid jwks uri")
    -- throw_expection(401, "AST00005", "Unauthorized")
  end
end

local function generate_assertion_token(conf, hash) 
  local private_key, err = load_keys(conf.keyset)
  for k, v in pairs(private_key) do
    log.info("private key values ", k, v)
    for x, y in pairs(v) do
      log.info("private value key values ", x, y)
    end
  end
  local jwk = private_key[conf.algorithm]
  log.info("Private key for algo ", conf.algorithm, " ", jwk)
  if not jwk then
    log.info("key not found")
    -- throw_expection(401, "AST00006", "Unauthorized")
  end
  local payload = {}
  payload.sub = 1234567890
  payload.name= 'John Doe'
  payload.admin= true
  payload.iat = 1516239022
  payload.hash = '185ba77795ef664e0dc8295a7ea20a62bfbfdd27180c6f5b5a98e31a46de943a'
  local signed_token
        signed_token, err = jws.encode({
          payload = payload,
          jwk     = jwk,
        })
  log.info("Generated token ", signed_token)
end

function JWTAssertionHandler:access(plugin_conf)

  log.debug("saying hi from the 'access' handler")
  
  -- log.inspect(plugin_conf)   -- check the logs for a pretty-printed config!
  local action = plugin_conf.action 
  local assertion_header_key = plugin_conf.assertion_header
  -- log.inspect(plugin_conf.include)
  local include = plugin_conf.include
  local headers = include.headers
  local delimiter = include.delimiter
  local is_include_method = include.method
  local is_include_uri = include.uri
  local is_include_payload = include.payload
  local req_headers = kong.request.get_header
  local fields_to_hash = ''
  local payload = kong.request.get_raw_body()
  if is_include_method == true then
    fields_to_hash = fields_to_hash..kong.request.get_method()..delimiter
  end
  if is_include_uri == true then
    fields_to_hash = fields_to_hash..kong.request.get_path_with_query()..delimiter
  end
  for _, header in ipairs(headers) do  
    log.info("request headers ", header)
    fields_to_hash = fields_to_hash..req_headers(header)..delimiter
    
  end
  log.info("value of include body", is_include_payload)

  if is_include_payload and not validate_body() then
    log.debug("payload validation failure")
    return false
  else 
    fields_to_hash = fields_to_hash..payload..delimiter
  end

  local hash, err = generate_assertion_hash(fields_to_hash)
  verify_assertion_token(plugin_conf, hash) -- based on action
  generate_assertion_token(plugin_conf, hash) -- based on the action
  log.info("work on signature")
  -- ngx.req.set_header(plugin_conf.request_header, "Kong jwt-assertion plugins rock - on the request!")
  log.info("request header value ", fields_to_hash)
end

-- runs in the 'header_filter_by_lua_block'
function JWTAssertionHandler:header_filter(plugin_conf)
  kong.log.debug("saying hi from the 'header_filter' handler")
  -- your custom code here, for example;
  -- ngx.header[plugin_conf.response_header] = " Kong jwt-assertion plugins - on the response!"

end


--[[ runs in the 'body_filter_by_lua_block'
function plugin:body_filter(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'body_filter' handler")

end --]]


--[[ runs in the 'log_by_lua_block'--]]

function JWTAssertionHandler:log(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'log' handler")

end 

return JWTAssertionHandler
