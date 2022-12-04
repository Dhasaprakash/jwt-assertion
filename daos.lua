-- to load the public and private keys from config/db
local schema = require "kong.db.schema"
local typedefs = require "kong.db.schema.typedefs"


local jwk = schema.define {
  type = "record",
  required = false,
  fields = {
    {
      issuer = {
        type = "string",
        required = false,
      },
    },
    {
      kty = {
        type = "string",
        required = false,
      },
    },
    {
      use = {
        type = "string",
        required = false,
      },
    },
    {
      key_ops = {
        type = "array",
        required = false,
        elements = {
          type = "string",
          required = false,
        }
      },
    },
    {
      alg = {
        type = "string",
        required = false,
      },
    },
    {
      kid = {
        type = "string",
        required = false,
      },
    },
    {
      x5u = {
        type = "string",
        required = false,
      },
    },
    {
      x5c = {
        type = "array",
        required = false,
        elements = {
          type = "string",
          required = false,
        },
      },
    },
    {
      x5t = {
        type = "string",
        required = false,
      },
    },
    {
      ["x5t#S256"] = {
        type = "string",
        required = false,
      },
    },
    {
      k = {
        type = "string",
        required = false,
      },
    },
    {
      x = {
        type = "string",
        required = false,
      },
    },
    {
      y = {
        type = "string",
        required = false,
      },
    },
    {
      crv = {
        type = "string",
        required = false,
      },
    },
    {
      n = {
        type = "string",
        required = false,
      },
    },
    {
      e = {
        type = "string",
        required = false,
      },
    },
    {
      d = {
        type = "string",
        required = false,
      },
    },
    {
      p = {
        type = "string",
        required = false,
      },
    },
    {
      q = {
        type = "string",
        required = false,
      },
    },
    {
      dp = {
        type = "string",
        required = false,
      },
    },
    {
      dq = {
        type = "string",
        required = false,
      },
    },
    {
      qi = {
        type = "string",
        required = false,
      },
    },
  },
}

return {
  jwt_assertion_jwks = {
    name                = "jwt_assertion_jwks",
    primary_key         = { "id" },
    cache_key           = { "name" },
    endpoint_key        = "name",
    generate_admin_api  = false,
    fields = {
      { id = typedefs.uuid },
      {
        name = {
          type= "string",
          required = true,
          unique = true,
        },
      },
      {
        keys = {
          type = "array",
          required = true,
          elements = jwk,
        },
      },
      {
        previous = {
          type = "array",
          required = false,
          elements = jwk,
        },
      },
      { created_at = typedefs.auto_timestamp_s },
      { updated_at = typedefs.auto_timestamp_s },
    },
  },
}
