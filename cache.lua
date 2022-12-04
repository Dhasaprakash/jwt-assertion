-- to cache both public and private keys to verify and sign payload respectively

require "kong.plugins.jwt-assertion.env"


local utils       = require "kong.tools.utils"
local codec       = require "kong.openid-connect.codec"
local token       = require "kong.openid-connect.token"
local jwks        = require "kong.openid-connect.jwks"
local keys        = require "kong.openid-connect.keys"
local hash        = require "kong.openid-connect.hash"
local log         = kong.log


local tablex      = require "pl.tablex"


local worker_id   = ngx.worker.id
local decode_args = ngx.decode_args
local encode_args = ngx.encode_args
local timer_at    = ngx.timer.at
local tonumber    = tonumber
local concat      = table.concat
local base64      = codec.base64
local ipairs      = ipairs
local time        = ngx.time
local find        = string.find
local type        = type
local null        = ngx.null
local kong        = kong


local KEYS = {}


local function cache_jwks(data)
  return data
end


local function warmup(premature)
  if premature then
    return
  end

  if kong and kong.db and kong.db.jwt_assertion_jwks then
    for row, err in kong.db.jwt_assertion_jwks:each() do
      if err then
        log.warn("warmup of jwks cache failed with: ", err)
        break
      end

      if row.name then
        local cache_key = kong.db.jwt_assertion_jwks:cache_key(row.name)
        kong.cache:get(cache_key, nil, cache_jwks, row)
      end
    end
  end
end


local function init_worker()
  KEYS = {}

  if worker_id() == 0 then
    local ok, err = timer_at(0, warmup)
    if not ok then
      log.warn("unable to create jwks cache warmup timer: ", err)
    end
  end

  if not kong.worker_events or not kong.worker_events.register then
    return
  end
end


local rediscover_keys


local function load_keys_db(name)
  log.info("loading jwks from database for ", name)

  local row, err = kong.db.jwt_assertion_jwks:select_by_name(name)

  if kong.configuration.database == "off" then
    log.info("Loading row -1 ", row)
    if not row then
      row = KEYS[name]
      log.info("Loading row -2 ", row)
      if row then
        log.info("Loading row -3 ", row)
        return row
      end

    else
      log.info("Loading row -4 ", row)
      KEYS[name] = row
    end
  end

  return row, err
end


local function rotate_keys(name, row, update, force, ret_err)
  local now = time()

  if find(name, "https://", 1, true) == 1 or find(name, "http://", 1, true) == 1 then
    if not row then
      log.info("loading jwks from ", name)

      local current_keys, err = keys.load(name, { ssl_verify = false, unwrap = true, json = false })
      log.info("keys loaded from url ", current_keys)

      if not current_keys then
        if ret_err then
          return nil, err
        end

        if kong.configuration.database == "off" and KEYS[name] then
          log.notice("loading jwks from ", name, " failed: ", err or "unknown error",
                     " (falling back to cached jwks)")
          row = KEYS[name]

        else
          log.notice("loading jwks from ", name, " failed: ", err or "unknown error",
                     " (falling back to empty jwks)")
          current_keys = {}
        end
      end

      if kong.configuration.database == "off" then
        if not row then
          row = {
            id = utils.uuid(),
            name = name,
            keys = current_keys,
            created_at = now,
            updated_at = now
          }
        end

      else
        local stored_data
        if not err then
          stored_data, err = kong.db.jwt_assertion_jwks:upsert_by_name(name, {
            keys = current_keys,
          })
        end
        if stored_data then
          row = stored_data

        else
          if ret_err then
            return nil, err
          end

          log.warn("unable to upsert ", name, " jwks to database (", err
                   or "unknown error", ")")

          stored_data, err = kong.db.jwt_assertion_jwks:select_by_name(name)
          if stored_data then
            row = stored_data

          else
            if err then
              if ret_err then
                return nil, err
              end

              log.warn("failed to load ", name, " jwks from database (", err ")")
            end

            if not row then
              row = {
                id = utils.uuid(),
                name = name,
                keys = current_keys,
                created_at = now,
                updated_at = now
              }
            end
          end
        end
      end

    elseif update ~= false then
      local updated_at = row.updated_at or 0

      if not force and now - updated_at < 300 then
        if ret_err then
          return nil, "jwks were rotated less than 5 minutes ago (skipping)"
        end

        log.notice("jwks were rotated less than 5 minutes ago (skipping)")

      else
        log.info("rotating jwks for ", name)

        local previous_keys = row.keys
        local current_keys, err = keys.load(name, { ssl_verify = false, unwrap = true, json = false })
        if current_keys then
          local id = {
            id = row.id
          }

          row = {
            name = name,
            keys = current_keys,
            previous = previous_keys,
            created_at = row.created_at or now,
            updated_at = now,
          }

          if kong.configuration.database == "off" then
            row.id = id.id or utils.uuid()
            KEYS[name] = row

          else
            local stored_data
            stored_data, err = kong.db.jwt_assertion_jwks:upsert(id, row)
            if stored_data then
              row = stored_data

            else
              if ret_err then
                return nil, err
              end

              log.warn("unable to upsert ", name, " jwks to database (", err
                       or "unknown error", ")")

              row.id = id.id
            end
          end

        else
          if ret_err then
            return nil, err
          end

          log.warn("failed to load ", name, " jwks from database (", err ")")
        end
      end
    end

    local options = {
      rediscover_keys = rediscover_keys(name, row)
    }

    return keys.new({ jwks_uri = name, options = options }, row.keys, row.previous)

  else
    if not row then
      log.info("creating jwks for ", name)

      local current_keys, err = jwks.new({ unwrap = true, json = false })
      if not current_keys then
        if ret_err then
          return nil, err
        end

        if kong.configuration.database == "off" and KEYS[name] then
          log.notice("creating jwks for ", name, " failed: ", err or "unknown error",
                     " (falling back to cached jwks)")
          row = KEYS[name]

        else
          log.warn("creating jwks for ", name, " failed: ", err or "unknown error",
                   " (falling back to empty configuration)")

          current_keys = {}
        end
      end

      if kong.configuration.database == "off" then
        if not row then
          row = {
            id   = utils.uuid(),
            name = name,
            keys = current_keys,
            created_at = now,
            updated_at = now,
          }
        end

      else
        local stored_data
        if not err then
          stored_data, err = kong.db.jwt_assertion_jwks:upsert_by_name(name, {
            keys = current_keys,
          })
        end
        if stored_data then
          row = stored_data

        else
          if ret_err then
            return nil, err
          end

          log.warn("unable to upsert ", name, " jwks to database (", err
                   or "unknown error", ")")

          stored_data, err = kong.db.jwt_assertion_jwks:select_by_name(name)
          if stored_data then
            row = stored_data

          else
            if err then
              if ret_err then
                return nil, err
              end

              log.warn("failed to load issuer ", name, " jwks from database (", err ")")
            end

            if not row then
              row = {
                id = utils.uuid(),
                name = name,
                keys = current_keys,
                created_at = now,
                updated_at = now
              }
            end
          end
        end
      end

    elseif update ~= false then
      log.info("rotating jwks for ", name)

      local previous_keys = row.keys
      local current_keys, err = jwks.new({ unwrap = true, json = false })
      if current_keys then
        local id = {
          id = row.id
        }

        row = {
          name = name,
          keys = current_keys,
          previous = previous_keys,
          created_at = row.created_at or now,
          updated_at = now,
        }

        if kong.configuration.database == "off" then
          row.id = id.id or utils.uuid()
          KEYS[name] = row

        else
          local stored_data
          stored_data, err = kong.db.jwt_assertion_jwks:upsert(id, row)
          if stored_data then
            row = stored_data

          else
            if ret_err then
              return nil, err
            end

            log.warn("unable to upsert ", name, " jwks to database (", err
                     or "unknown error", ")")

            row.id = id.id
          end
        end

      else
        if ret_err then
          return nil, err
        end

        log.warn("failed to create keys for ", name, " (", err ")")
      end
    end

    return keys.new({}, row.keys, row.previous)
  end
end


rediscover_keys = function(name, row)
  return function()
    log.info("rediscovering keys for ", name)
    return rotate_keys(name, row)
  end
end

-- plugin is developed for db-less kong
local function load_keys(name)
  kong.configuration.database = "off"
  log.info("load keys ", name)
  local cache_key = kong.db.jwt_assertion_jwks:cache_key(name)
  log.info("chache  keys from db ", cache_key)
  local row, err = kong.cache:get(cache_key, nil, load_keys_db, name)
  if err then
    log.info(err)
  end

  return rotate_keys(name, row, false)
end

return {
  init_worker   = init_worker,
  load_keys     = load_keys,
  rotate_keys   = rotate_keys,
  keys          = keys,
}
