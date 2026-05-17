--[[
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                   ANTI-TAMPER PROTECTION SYSTEM                     ║
    ║                        Lua 5.1 Compatible                          ║
    ║                                                                    ║
    ║  Kapsamlı koruma modülü:                                           ║
    ║  • Environment Protection (Ortam Koruma)                           ║
    ║  • Function Integrity (Fonksiyon Bütünlük Kontrolü)                ║
    ║  • Debug Library Lockdown (Debug Kütüphanesi Kilitleme)            ║
    ║  • Bytecode Validation (Bytecode Doğrulama)                        ║
    ║  • Runtime Integrity Checks (Çalışma Zamanı Bütünlük)             ║
    ║  • Anti-Hook Mechanisms (Kanca Önleme)                             ║
    ║  • Metatable Protection (Metatable Koruma)                         ║
    ║  • Heartbeat System (Kalp Atışı Sistemi)                           ║
    ║  • Tamper Event Callbacks (Olay Geri Çağırma)                      ║
    ║  • Stack Integrity (Yığın Bütünlüğü)                               ║
    ║  • Upvalue Protection (Upvalue Koruma)                              ║
    ║  • String Obfuscation Helpers (Metin Gizleme)                      ║
    ║  • Module Isolation (Modül İzolasyonu)                              ║
    ║  • Timing Attack Detection (Zamanlama Saldırı Tespiti)             ║
    ╚══════════════════════════════════════════════════════════════════════╝
--]]

-- Lua 5.1 uyumluluk kontrolü
assert(_VERSION == "Lua 5.1", "Bu modul sadece Lua 5.1 ile uyumludur!")

-------------------------------------------------------------------------------
-- Orijinal referansları sakla (tamper öncesi)
-------------------------------------------------------------------------------
local _rawget       = rawget
local _rawset       = rawset
local _rawequal     = rawequal
local _type         = type
local _tostring     = tostring
local _tonumber     = tonumber
local _select       = select
local _unpack       = unpack
local _pcall        = pcall
local _xpcall       = xpcall
local _error        = error
local _assert       = assert
local _pairs        = pairs
local _ipairs       = ipairs
local _next         = next
local _setmetatable = setmetatable
local _getmetatable = getmetatable
local _setfenv      = setfenv
local _getfenv      = getfenv
local _loadstring   = loadstring
local _load         = load
local _dofile       = dofile
local _loadfile     = loadfile
local _require      = require
local _newproxy     = newproxy
local _collectgarbage = collectgarbage
local _coroutine_create = coroutine.create
local _coroutine_resume = coroutine.resume
local _coroutine_yield  = coroutine.yield
local _coroutine_wrap   = coroutine.wrap

local _string_byte   = string.byte
local _string_char   = string.char
local _string_sub    = string.sub
local _string_len    = string.len
local _string_rep    = string.rep
local _string_reverse = string.reverse
local _string_format = string.format
local _string_find   = string.find
local _string_gsub   = string.gsub
local _string_dump   = string.dump
local _string_match  = string.match
local _string_gmatch = string.gmatch
local _string_lower  = string.lower
local _string_upper  = string.upper

local _table_insert  = table.insert
local _table_remove  = table.remove
local _table_concat  = table.concat
local _table_sort    = table.sort

local _math_floor    = math.floor
local _math_random   = math.random
local _math_abs      = math.abs
local _math_fmod     = math.fmod
local _math_huge     = math.huge
local _math_ceil     = math.ceil
local _math_max      = math.max
local _math_min      = math.min
local _math_randomseed = math.randomseed

local _os_clock      = os.clock
local _os_time       = os.time
local _os_difftime   = os.difftime

local _debug_getinfo    = debug and debug.getinfo
local _debug_getlocal   = debug and debug.getlocal
local _debug_getupvalue = debug and debug.getupvalue
local _debug_setupvalue = debug and debug.setupvalue
local _debug_sethook    = debug and debug.sethook
local _debug_gethook    = debug and debug.gethook
local _debug_getfenv    = debug and debug.getfenv
local _debug_setfenv    = debug and debug.setfenv

-------------------------------------------------------------------------------
-- Ana modül tablosu
-------------------------------------------------------------------------------
local AntiTamper = {}
AntiTamper.__index = AntiTamper

-- İç durum değişkenleri
local _state = {
    initialized       = false,
    integrity_map     = {},       -- fonksiyon hash'leri
    protected_tables  = {},       -- korunan tablolar
    protected_funcs   = {},       -- korunan fonksiyonlar
    env_snapshot      = {},       -- ortam anlık görüntüsü
    callbacks         = {},       -- tamper olay geri çağırmaları
    heartbeat_active  = false,    -- kalp atışı durumu
    heartbeat_co      = nil,      -- kalp atışı coroutine
    heartbeat_interval = 0.1,    -- kalp atışı aralığı (saniye)
    last_heartbeat    = 0,        -- son kalp atışı zamanı
    violation_count   = 0,        -- ihlal sayacı
    max_violations    = 5,        -- maksimum ihlal
    tamper_detected   = false,    -- tamper algılandı mı
    checksum_seed     = 0,        -- checksum tohum değeri
    timing_threshold  = 0.05,    -- zamanlama eşiği (saniye)
    stack_canaries    = {},       -- yığın kanarya değerleri
    protected_upvalues = {},     -- korunan upvalue'lar
    module_hashes     = {},       -- modül hash'leri
    execution_tokens  = {},       -- yürütme tokenları
    obfuscation_key   = 0,        -- gizleme anahtarı
    debug_locked      = false,    -- debug kilitli mi
    env_locked        = false,    -- ortam kilitli mi
    hook_traps        = {},       -- hook tuzakları
    watermarks        = {},       -- dijital filigranlar
    log               = {},       -- olay günlüğü
    log_max           = 1000,     -- maksimum günlük girişi
    fingerprint       = "",       -- sistem parmak izi
}

-------------------------------------------------------------------------------
-- BÖLÜM 1: Yardımcı Fonksiyonlar (Utility Functions)
-------------------------------------------------------------------------------

-- Basit ama etkili hash fonksiyonu (Lua 5.1 uyumlu, harici bağımlılık yok)
local function compute_hash(data)
    local hash = 5381
    local str = _tostring(data) or ""
    for i = 1, _string_len(str) do
        local c = _string_byte(str, i)
        -- djb2 hash algoritması
        hash = _math_fmod((hash * 33 + c), 2^32)
    end
    return hash
end

-- Gelişmiş hash: FNV-1a varyantı
local function compute_hash_fnv(data)
    local hash = 2166136261
    local str = _tostring(data) or ""
    for i = 1, _string_len(str) do
        local c = _string_byte(str, i)
        hash = _math_fmod(hash * 16777619, 2^32)
        -- XOR with bit manipulation (Lua 5.1 uyumlu)
        local xor_result = 0
        local a, b = hash, c
        local p = 1
        for _ = 1, 32 do
            local ra = _math_fmod(a, 2)
            local rb = _math_fmod(b, 2)
            if ra ~= rb then
                xor_result = xor_result + p
            end
            a = _math_floor(a / 2)
            b = _math_floor(b / 2)
            p = p * 2
        end
        hash = xor_result
    end
    return hash
end

-- Çift hash: iki algoritmayı birleştir
local function compute_dual_hash(data)
    local h1 = compute_hash(data)
    local h2 = compute_hash_fnv(data)
    return _string_format("%X:%X", h1, h2)
end

-- Fonksiyon bytecode hash'i
local function compute_function_hash(func)
    if _type(func) ~= "function" then
        return nil
    end
    local ok, bytecode = _pcall(_string_dump, func)
    if not ok or not bytecode then
        return nil
    end
    return compute_dual_hash(bytecode)
end

-- Güvenli zaman ölçümü
local function get_time()
    return _os_clock()
end

-- Rastgele canary değeri üret
local function generate_canary()
    return _math_floor(_math_random() * 2^31) + _os_time()
end

-- XOR tabanlı basit şifreleme (Lua 5.1 uyumlu)
local function xor_byte(a, b)
    local result = 0
    local p = 1
    for _ = 1, 8 do
        local ra = _math_fmod(a, 2)
        local rb = _math_fmod(b, 2)
        if ra ~= rb then
            result = result + p
        end
        a = _math_floor(a / 2)
        b = _math_floor(b / 2)
        p = p * 2
    end
    return result
end

-- String XOR şifreleme/çözme
local function xor_string(str, key)
    local result = {}
    local key_str = _tostring(key)
    local key_len = _string_len(key_str)
    for i = 1, _string_len(str) do
        local s_byte = _string_byte(str, i)
        local k_byte = _string_byte(key_str, ((i - 1) % key_len) + 1)
        _table_insert(result, _string_char(xor_byte(s_byte, k_byte)))
    end
    return _table_concat(result)
end

-- Derin tablo kopyalama
local function deep_copy(obj, seen)
    if _type(obj) ~= "table" then return obj end
    seen = seen or {}
    if seen[obj] then return seen[obj] end
    local copy = {}
    seen[obj] = copy
    for k, v in _pairs(obj) do
        copy[deep_copy(k, seen)] = deep_copy(v, seen)
    end
    local mt = _getmetatable(obj)
    if mt then
        _setmetatable(copy, deep_copy(mt, seen))
    end
    return copy
end

-- Olay günlüğüne yaz
local function log_event(event_type, details)
    local entry = {
        time = _os_time(),
        clock = _os_clock(),
        event = event_type,
        details = details or ""
    }
    _table_insert(_state.log, entry)
    -- Günlük boyutu sınırla
    while #_state.log > _state.log_max do
        _table_remove(_state.log, 1)
    end
end

-- Geri çağırma tetikleme
local function trigger_callback(event_type, info)
    _state.violation_count = _state.violation_count + 1
    _state.tamper_detected = true

    log_event(event_type, _tostring(info))

    local callbacks = _state.callbacks[event_type]
    if callbacks then
        for i = 1, #callbacks do
            local ok, err = _pcall(callbacks[i], event_type, info)
            if not ok then
                log_event("callback_error", _tostring(err))
            end
        end
    end

    -- Genel tamper callback
    local general = _state.callbacks["tamper"]
    if general then
        for i = 1, #general do
            local ok, err = _pcall(general[i], event_type, info)
            if not ok then
                log_event("callback_error", _tostring(err))
            end
        end
    end

    -- Maksimum ihlale ulaşıldığında
    if _state.violation_count >= _state.max_violations then
        local critical = _state.callbacks["critical"]
        if critical then
            for i = 1, #critical do
                _pcall(critical[i], "critical_violation_limit",
                    _string_format("Ihlal limiti asildi: %d/%d",
                        _state.violation_count, _state.max_violations))
            end
        end
    end
end

-------------------------------------------------------------------------------
-- BÖLÜM 2: Environment Protection (Ortam Koruma)
-------------------------------------------------------------------------------

-- Global ortam anlık görüntüsünü al
function AntiTamper.snapshot_environment(env)
    env = env or _getfenv(0)
    local snapshot = {}
    for k, v in _pairs(env) do
        if _type(v) == "function" then
            snapshot[k] = {
                type = "function",
                hash = compute_function_hash(v),
                ref  = v
            }
        elseif _type(v) == "table" then
            snapshot[k] = {
                type = "table",
                keys = {},
                ref  = v
            }
            for tk, tv in _pairs(v) do
                snapshot[k].keys[tk] = _type(tv)
            end
        else
            snapshot[k] = {
                type  = _type(v),
                value = v
            }
        end
    end
    _state.env_snapshot = snapshot
    log_event("env_snapshot", "Ortam goruntusu alindi")
    return snapshot
end

-- Ortam bütünlüğünü doğrula
function AntiTamper.verify_environment(env)
    env = env or _getfenv(0)
    local snapshot = _state.env_snapshot
    if not snapshot or not _next(snapshot) then
        return false, "Ortam goruntusu bulunamadi"
    end

    local violations = {}

    for k, info in _pairs(snapshot) do
        local current = _rawget(env, k)

        if current == nil then
            _table_insert(violations, {
                key = k,
                violation = "removed",
                expected = info.type,
                got = "nil"
            })
        elseif info.type == "function" then
            if _type(current) ~= "function" then
                _table_insert(violations, {
                    key = k,
                    violation = "type_changed",
                    expected = "function",
                    got = _type(current)
                })
            elseif info.hash then
                local current_hash = compute_function_hash(current)
                if current_hash ~= info.hash then
                    _table_insert(violations, {
                        key = k,
                        violation = "function_modified",
                        expected_hash = info.hash,
                        current_hash = current_hash
                    })
                end
            end
        elseif info.type == "table" then
            if _type(current) ~= "table" then
                _table_insert(violations, {
                    key = k,
                    violation = "type_changed",
                    expected = "table",
                    got = _type(current)
                })
            elseif not _rawequal(current, info.ref) then
                _table_insert(violations, {
                    key = k,
                    violation = "table_replaced",
                })
            end
        else
            if _type(current) ~= info.type then
                _table_insert(violations, {
                    key = k,
                    violation = "type_changed",
                    expected = info.type,
                    got = _type(current)
                })
            end
        end
    end

    -- Yeni eklenen anahtarları kontrol et
    for k, _ in _pairs(env) do
        if not snapshot[k] then
            _table_insert(violations, {
                key = k,
                violation = "new_key_added",
                type = _type(_rawget(env, k))
            })
        end
    end

    if #violations > 0 then
        for _, v in _ipairs(violations) do
            trigger_callback("env_violation", v)
        end
        return false, violations
    end

    return true
end

-- Ortamı kilitle (yazma korumalı proxy)
function AntiTamper.lock_environment(env, whitelist)
    env = env or _getfenv(2)
    whitelist = whitelist or {}

    local whitelist_map = {}
    for _, k in _ipairs(whitelist) do
        whitelist_map[k] = true
    end

    -- Önce mevcut durumu kaydet
    AntiTamper.snapshot_environment(env)

    local proxy = _newproxy(true)
    local mt = _getmetatable(proxy)

    mt.__index = function(_, key)
        return _rawget(env, key)
    end

    mt.__newindex = function(_, key, value)
        if whitelist_map[key] then
            _rawset(env, key, value)
            return
        end

        trigger_callback("env_write_blocked", {
            key = key,
            value_type = _type(value),
            action = "blocked"
        })
    end

    mt.__tostring = function()
        return "protected_environment"
    end

    _state.env_locked = true
    log_event("env_locked", "Ortam kilitlendi")
    return proxy
end

-------------------------------------------------------------------------------
-- BÖLÜM 3: Function Integrity (Fonksiyon Bütünlük Kontrolü)
-------------------------------------------------------------------------------

-- Fonksiyonu kayıt altına al
function AntiTamper.register_function(name, func)
    if _type(func) ~= "function" then
        _error("register_function: fonksiyon bekleniyor, " .. _type(func) .. " verildi")
    end

    local hash = compute_function_hash(func)
    local info = _debug_getinfo and _debug_getinfo(func, "S") or {}

    _state.integrity_map[name] = {
        hash        = hash,
        ref         = func,
        source      = info.source or "unknown",
        linedefined = info.linedefined or 0,
        registered  = _os_time(),
        check_count = 0,
        last_check  = 0
    }

    log_event("func_registered", name)
    return hash
end

-- Birden fazla fonksiyonu kaydet
function AntiTamper.register_functions(func_table)
    local results = {}
    for name, func in _pairs(func_table) do
        if _type(func) == "function" then
            results[name] = AntiTamper.register_function(name, func)
        end
    end
    return results
end

-- Tek fonksiyon bütünlüğünü doğrula
function AntiTamper.verify_function(name, func)
    local record = _state.integrity_map[name]
    if not record then
        return false, "Fonksiyon kayitli degil: " .. _tostring(name)
    end

    func = func or record.ref
    local current_hash = compute_function_hash(func)

    record.check_count = record.check_count + 1
    record.last_check = _os_time()

    if current_hash ~= record.hash then
        trigger_callback("function_tampered", {
            name = name,
            expected = record.hash,
            got = current_hash,
            source = record.source
        })
        return false, "Fonksiyon degistirildi: " .. name
    end

    -- Referans kontrolü
    if not _rawequal(func, record.ref) then
        trigger_callback("function_replaced", {
            name = name,
            action = "reference_changed"
        })
        return false, "Fonksiyon referansi degisti: " .. name
    end

    return true
end

-- Tüm kayıtlı fonksiyonları doğrula
function AntiTamper.verify_all_functions()
    local all_ok = true
    local failures = {}

    for name, _ in _pairs(_state.integrity_map) do
        local ok, msg = AntiTamper.verify_function(name)
        if not ok then
            all_ok = false
            _table_insert(failures, { name = name, reason = msg })
        end
    end

    return all_ok, failures
end

-- Korumalı fonksiyon sarmalayıcı (wrapper) oluştur
function AntiTamper.protect_function(name, func)
    if _type(func) ~= "function" then
        _error("protect_function: fonksiyon bekleniyor")
    end

    AntiTamper.register_function(name, func)

    local protected = function(...)
        -- Her çağrıda bütünlük kontrolü
        local ok, msg = AntiTamper.verify_function(name, func)
        if not ok then
            trigger_callback("protected_call_blocked", {
                name = name,
                reason = msg
            })
            _error("Anti-tamper: Korunmus fonksiyon degistirildi - " .. name)
        end

        return func(...)
    end

    _state.protected_funcs[name] = {
        original  = func,
        protected = protected,
        hash      = compute_function_hash(func)
    }

    return protected
end

-------------------------------------------------------------------------------
-- BÖLÜM 4: Debug Library Lockdown (Debug Kütüphanesi Kilitleme)
-------------------------------------------------------------------------------

-- Debug kütüphanesini tamamen kilitle
function AntiTamper.lock_debug_library()
    if _state.debug_locked then
        return true, "Debug zaten kilitli"
    end

    -- Orijinal debug fonksiyonlarını sakla (iç kullanım için)
    local _saved_debug = {}
    if debug then
        for k, v in _pairs(debug) do
            _saved_debug[k] = v
        end
    end

    -- Tehlikeli debug fonksiyonlarını devre dışı bırak
    local dangerous_funcs = {
        "sethook", "setlocal", "setupvalue", "setfenv",
        "setmetatable", "debug"
    }

    if debug then
        for _, fname in _ipairs(dangerous_funcs) do
            if debug[fname] then
                debug[fname] = function(...)
                    trigger_callback("debug_access_blocked", {
                        func = fname,
                        action = "blocked"
                    })
                    _error("Anti-tamper: debug." .. fname .. " erisimi engellendi")
                end
            end
        end

        -- getinfo'yu sınırla (sadece temel bilgi)
        local original_getinfo = _debug_getinfo
        if original_getinfo then
            debug.getinfo = function(func_or_level, what)
                -- Sadece temel bilgiye izin ver
                what = what or "nSl"
                -- Upvalue ve local bilgisini engelle
                what = _string_gsub(what, "u", "")
                what = _string_gsub(what, "f", "")
                local result = original_getinfo(func_or_level, what)
                if result then
                    result.func = nil -- Fonksiyon referansını gizle
                end
                return result
            end
        end

        -- getupvalue'u sınırla
        local original_getupvalue = _debug_getupvalue
        if original_getupvalue then
            debug.getupvalue = function(func, up)
                trigger_callback("debug_getupvalue_attempt", {
                    action = "limited"
                })
                local name, _ = original_getupvalue(func, up)
                return name, nil -- Değeri gizle
            end
        end
    end

    _state.debug_locked = true
    log_event("debug_locked", "Debug kutuphanesi kilitlendi")
    return true
end

-- Debug kütüphanesini tamamen kaldır
function AntiTamper.remove_debug_library()
    AntiTamper.lock_debug_library()

    -- Global'den kaldır
    local env = _getfenv(0)
    _rawset(env, "debug", nil)

    log_event("debug_removed", "Debug kutuphanesi kaldirildi")
    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 5: Bytecode Validation (Bytecode Doğrulama)
-------------------------------------------------------------------------------

-- Lua 5.1 bytecode header doğrulama
function AntiTamper.validate_bytecode(bytecode)
    if _type(bytecode) ~= "string" then
        return false, "Gecersiz bytecode tipi"
    end

    if _string_len(bytecode) < 12 then
        return false, "Bytecode cok kisa"
    end

    -- Lua 5.1 signature: \27Lua
    local sig = _string_sub(bytecode, 1, 4)
    if sig ~= "\27Lua" then
        return false, "Gecersiz Lua signature"
    end

    -- Versiyon kontrolü: 0x51 = Lua 5.1
    local version = _string_byte(bytecode, 5)
    if version ~= 0x51 then
        return false, _string_format("Yanlis Lua versiyonu: 0x%02X (beklenen: 0x51)", version)
    end

    -- Format kontrolü
    local format = _string_byte(bytecode, 6)
    if format ~= 0 then
        return false, "Resmi olmayan bytecode formati"
    end

    -- Endianness kontrolü
    local endianness = _string_byte(bytecode, 7)
    if endianness ~= 1 and endianness ~= 0 then
        return false, "Gecersiz endianness"
    end

    -- int boyutu
    local int_size = _string_byte(bytecode, 8)
    if int_size ~= 4 then
        return false, "Beklenmeyen int boyutu: " .. _tostring(int_size)
    end

    -- size_t boyutu
    local size_t_size = _string_byte(bytecode, 9)
    if size_t_size ~= 4 and size_t_size ~= 8 then
        return false, "Beklenmeyen size_t boyutu: " .. _tostring(size_t_size)
    end

    -- Instruction boyutu
    local instr_size = _string_byte(bytecode, 10)
    if instr_size ~= 4 then
        return false, "Beklenmeyen instruction boyutu: " .. _tostring(instr_size)
    end

    -- lua_Number boyutu
    local number_size = _string_byte(bytecode, 11)
    if number_size ~= 8 and number_size ~= 4 then
        return false, "Beklenmeyen lua_Number boyutu: " .. _tostring(number_size)
    end

    -- İntegral bayrak
    local integral = _string_byte(bytecode, 12)
    if integral ~= 0 and integral ~= 1 then
        return false, "Gecersiz integral bayrak"
    end

    return true, "Bytecode gecerli"
end

-- Fonksiyonun bytecode'unu doğrula
function AntiTamper.validate_function_bytecode(func)
    if _type(func) ~= "function" then
        return false, "Fonksiyon bekleniyor"
    end

    local ok, bytecode = _pcall(_string_dump, func)
    if not ok then
        return false, "Bytecode alinamadi (C fonksiyonu olabilir)"
    end

    return AntiTamper.validate_bytecode(bytecode)
end

-- Bytecode'a zararlı pattern enjeksiyonu kontrolü
function AntiTamper.check_bytecode_injection(func)
    if _type(func) ~= "function" then
        return false, "Fonksiyon bekleniyor"
    end

    local ok, bytecode = _pcall(_string_dump, func)
    if not ok then
        return true -- C fonksiyonları için geç
    end

    -- Şüpheli pattern'leri kontrol et
    local suspicious_patterns = {
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", -- Uzun null dizisi (NOP sled)
        "\27Lua",                              -- İç içe bytecode (injection)
    }

    -- İlk 12 byte'tan sonra iç içe signature ara
    local inner = _string_sub(bytecode, 13)
    for _, pattern in _ipairs(suspicious_patterns) do
        if pattern == "\27Lua" then
            if _string_find(inner, pattern, 1, true) then
                trigger_callback("bytecode_injection", {
                    pattern = "nested_signature",
                    func = _tostring(func)
                })
                return false, "Ic ice bytecode signature tespit edildi"
            end
        end
    end

    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 6: Runtime Integrity Checks (Çalışma Zamanı Bütünlük Kontrolleri)
-------------------------------------------------------------------------------

-- Kritik Lua fonksiyonlarının bütünlüğünü doğrula
function AntiTamper.verify_runtime_integrity()
    local violations = {}

    -- Kritik fonksiyonları kontrol et
    local critical_checks = {
        { name = "type",         ref = _type,          current = type },
        { name = "tostring",     ref = _tostring,      current = tostring },
        { name = "tonumber",     ref = _tonumber,      current = tonumber },
        { name = "pairs",        ref = _pairs,         current = pairs },
        { name = "ipairs",       ref = _ipairs,        current = ipairs },
        { name = "next",         ref = _next,          current = next },
        { name = "rawget",       ref = _rawget,        current = rawget },
        { name = "rawset",       ref = _rawset,        current = rawset },
        { name = "rawequal",     ref = _rawequal,      current = rawequal },
        { name = "pcall",        ref = _pcall,         current = pcall },
        { name = "xpcall",       ref = _xpcall,        current = xpcall },
        { name = "setmetatable", ref = _setmetatable,  current = setmetatable },
        { name = "getmetatable", ref = _getmetatable,  current = getmetatable },
        { name = "error",        ref = _error,         current = error },
        { name = "assert",       ref = _assert,        current = assert },
        { name = "select",       ref = _select,        current = select },
        { name = "unpack",       ref = _unpack,        current = unpack },
        { name = "loadstring",   ref = _loadstring,    current = loadstring },
        { name = "setfenv",      ref = _setfenv,       current = setfenv },
        { name = "getfenv",      ref = _getfenv,       current = getfenv },
        { name = "require",      ref = _require,       current = require },
        { name = "collectgarbage", ref = _collectgarbage, current = collectgarbage },
    }

    for _, check in _ipairs(critical_checks) do
        if not _rawequal(check.ref, check.current) then
            _table_insert(violations, {
                name = check.name,
                violation = "function_replaced",
                original_type = _type(check.ref),
                current_type = _type(check.current)
            })
            trigger_callback("runtime_integrity", {
                name = check.name,
                violation = "critical_function_replaced"
            })
        end
    end

    -- String kütüphanesi kontrolü
    local string_checks = {
        { name = "string.byte",    ref = _string_byte,    current = string.byte },
        { name = "string.char",    ref = _string_char,    current = string.char },
        { name = "string.dump",    ref = _string_dump,    current = string.dump },
        { name = "string.find",    ref = _string_find,    current = string.find },
        { name = "string.format",  ref = _string_format,  current = string.format },
        { name = "string.gsub",    ref = _string_gsub,    current = string.gsub },
        { name = "string.len",     ref = _string_len,     current = string.len },
        { name = "string.sub",     ref = _string_sub,     current = string.sub },
        { name = "string.rep",     ref = _string_rep,     current = string.rep },
        { name = "string.reverse", ref = _string_reverse, current = string.reverse },
    }

    for _, check in _ipairs(string_checks) do
        if not _rawequal(check.ref, check.current) then
            _table_insert(violations, {
                name = check.name,
                violation = "function_replaced"
            })
            trigger_callback("runtime_integrity", {
                name = check.name,
                violation = "string_library_tampered"
            })
        end
    end

    -- Table kütüphanesi kontrolü
    local table_checks = {
        { name = "table.insert",  ref = _table_insert,  current = table.insert },
        { name = "table.remove",  ref = _table_remove,  current = table.remove },
        { name = "table.concat",  ref = _table_concat,  current = table.concat },
        { name = "table.sort",    ref = _table_sort,     current = table.sort },
    }

    for _, check in _ipairs(table_checks) do
        if not _rawequal(check.ref, check.current) then
            _table_insert(violations, {
                name = check.name,
                violation = "function_replaced"
            })
            trigger_callback("runtime_integrity", {
                name = check.name,
                violation = "table_library_tampered"
            })
        end
    end

    -- Math kütüphanesi kontrolü
    local math_checks = {
        { name = "math.floor",  ref = _math_floor,  current = math.floor },
        { name = "math.random", ref = _math_random,  current = math.random },
        { name = "math.abs",    ref = _math_abs,     current = math.abs },
    }

    for _, check in _ipairs(math_checks) do
        if not _rawequal(check.ref, check.current) then
            _table_insert(violations, {
                name = check.name,
                violation = "function_replaced"
            })
            trigger_callback("runtime_integrity", {
                name = check.name,
                violation = "math_library_tampered"
            })
        end
    end

    if #violations > 0 then
        return false, violations
    end
    return true
end

-- Standart kütüphane tablosunun kendisinin değiştirilip değiştirilmediğini kontrol et
function AntiTamper.verify_standard_libraries()
    local violations = {}
    local libs = {
        { name = "string", ref = string },
        { name = "table",  ref = table },
        { name = "math",   ref = math },
        { name = "os",     ref = os },
        { name = "io",     ref = io },
        { name = "coroutine", ref = coroutine },
    }

    for _, lib in _ipairs(libs) do
        local current = _rawget(_getfenv(0), lib.name)
        if current == nil then
            _table_insert(violations, {
                name = lib.name,
                violation = "library_removed"
            })
        elseif not _rawequal(current, lib.ref) then
            _table_insert(violations, {
                name = lib.name,
                violation = "library_replaced"
            })
        end
    end

    if #violations > 0 then
        trigger_callback("library_tamper", violations)
        return false, violations
    end
    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 7: Anti-Hook Mechanisms (Kanca Önleme Mekanizmaları)
-------------------------------------------------------------------------------

-- Hook kontrolü yap
function AntiTamper.check_hooks()
    if not _debug_gethook then
        return true -- debug mevcut değilse hook da yok
    end

    local hook, mask, count = _debug_gethook()

    if hook ~= nil then
        trigger_callback("hook_detected", {
            mask = mask or "unknown",
            count = count or 0,
            hook_type = _type(hook)
        })
        return false, "Hook tespit edildi"
    end

    return true
end

-- Hook'ları temizle
function AntiTamper.clear_hooks()
    if _debug_sethook then
        _debug_sethook() -- Hook'u temizle
        log_event("hooks_cleared", "Tum hook'lar temizlendi")
    end
    return true
end

-- Anti-hook tuzağı kur
function AntiTamper.set_hook_trap()
    if not _debug_sethook or not _debug_gethook then
        return false, "Debug kutuphanesi mevcut degil"
    end

    -- Periyodik olarak hook kontrolü yapan bir sistem
    local trap_id = generate_canary()
    _state.hook_traps[trap_id] = {
        active = true,
        created = _os_time(),
        check_count = 0
    }

    log_event("hook_trap_set", "Hook tuzagi kuruldu: " .. _tostring(trap_id))
    return true, trap_id
end

-- Hook tuzaklarını çalıştır
function AntiTamper.run_hook_traps()
    local violations = {}

    for id, trap in _pairs(_state.hook_traps) do
        if trap.active then
            trap.check_count = trap.check_count + 1

            local ok, msg = AntiTamper.check_hooks()
            if not ok then
                _table_insert(violations, {
                    trap_id = id,
                    message = msg
                })
            end
        end
    end

    if #violations > 0 then
        return false, violations
    end
    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 8: Metatable Protection (Metatable Koruma)
-------------------------------------------------------------------------------

-- Tabloyu metatable değişikliklerine karşı koru
function AntiTamper.protect_metatable(tbl, mt)
    if _type(tbl) ~= "table" then
        _error("protect_metatable: tablo bekleniyor")
    end

    mt = mt or _getmetatable(tbl) or {}

    -- __metatable ayarla (getmetatable'ı engelle)
    mt.__metatable = "protected"

    -- Orijinal metatable'ı sakla
    local mt_hash = compute_hash(_tostring(mt))
    _state.protected_tables[_tostring(tbl)] = {
        ref     = tbl,
        mt_ref  = mt,
        mt_hash = mt_hash,
        created = _os_time()
    }

    _setmetatable(tbl, mt)
    log_event("metatable_protected", _tostring(tbl))
    return tbl
end

-- Salt okunur tablo oluştur
function AntiTamper.make_readonly(tbl, name)
    name = name or _tostring(tbl)

    local proxy = {}
    local mt = {
        __index = tbl,
        __newindex = function(_, key, value)
            trigger_callback("readonly_violation", {
                table_name = name,
                key = _tostring(key),
                value_type = _type(value),
                action = "write_blocked"
            })
            _error("Anti-tamper: Salt okunur tabloya yazma denemesi - " .. name)
        end,
        __metatable = "readonly",
        __len = function()
            return #tbl
        end,
        __pairs = function()
            return _pairs(tbl)
        end,
        __ipairs = function()
            return _ipairs(tbl)
        end,
        __tostring = function()
            return "readonly<" .. name .. ">"
        end,
    }

    _setmetatable(proxy, mt)
    log_event("readonly_created", name)
    return proxy
end

-- Derin salt okunur: iç içe tabloları da koru
function AntiTamper.make_deep_readonly(tbl, name, seen)
    name = name or _tostring(tbl)
    seen = seen or {}

    if seen[tbl] then return seen[tbl] end

    local proxy = {}
    seen[tbl] = proxy

    for k, v in _pairs(tbl) do
        if _type(v) == "table" and not seen[v] then
            -- İç tabloyu da salt okunur yap
            AntiTamper.make_deep_readonly(v, name .. "." .. _tostring(k), seen)
        end
    end

    local mt = {
        __index = function(_, key)
            local value = tbl[key]
            if _type(value) == "table" and seen[value] then
                return seen[value]
            end
            return value
        end,
        __newindex = function(_, key, _)
            trigger_callback("deep_readonly_violation", {
                table_name = name,
                key = _tostring(key),
                action = "write_blocked"
            })
            _error("Anti-tamper: Derin salt okunur tabloya yazma - " .. name .. "." .. _tostring(key))
        end,
        __metatable = "deep_readonly",
        __len = function()
            return #tbl
        end,
        __tostring = function()
            return "deep_readonly<" .. name .. ">"
        end,
    }

    _setmetatable(proxy, mt)
    return proxy
end

-- Korunan tabloların bütünlüğünü doğrula
function AntiTamper.verify_protected_tables()
    local violations = {}

    for key, info in _pairs(_state.protected_tables) do
        local tbl = info.ref
        if _type(tbl) ~= "table" then
            _table_insert(violations, {
                key = key,
                violation = "table_destroyed"
            })
        else
            local current_mt = _rawget(_getmetatable(tbl) or {}, "__metatable")
                            or _getmetatable(tbl)
            if current_mt ~= "protected" and current_mt ~= info.mt_ref then
                _table_insert(violations, {
                    key = key,
                    violation = "metatable_changed"
                })
            end
        end
    end

    if #violations > 0 then
        trigger_callback("metatable_tamper", violations)
        return false, violations
    end
    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 9: Heartbeat System (Kalp Atışı Sistemi)
-------------------------------------------------------------------------------

-- Kalp atışı oluştur
function AntiTamper.create_heartbeat(config)
    config = config or {}

    _state.heartbeat_interval = config.interval or 0.1
    _state.heartbeat_active   = true
    _state.last_heartbeat     = get_time()

    -- Her kalp atışında çalışacak kontroller
    local checks = config.checks or {
        "runtime_integrity",
        "hooks",
        "environment",
        "functions",
        "protected_tables",
        "standard_libraries",
        "stack_canaries",
        "timing"
    }

    local check_map = {
        runtime_integrity   = AntiTamper.verify_runtime_integrity,
        hooks               = AntiTamper.check_hooks,
        environment         = AntiTamper.verify_environment,
        functions           = AntiTamper.verify_all_functions,
        protected_tables    = AntiTamper.verify_protected_tables,
        standard_libraries  = AntiTamper.verify_standard_libraries,
        stack_canaries      = AntiTamper.verify_stack_canaries,
        timing              = AntiTamper.check_timing_attack,
    }

    -- Heartbeat fonksiyonu
    local function heartbeat_tick()
        if not _state.heartbeat_active then
            return false
        end

        local now = get_time()
        local elapsed = now - _state.last_heartbeat

        -- Zamanlama anomalisi kontrolü
        if elapsed > _state.heartbeat_interval * 10 then
            trigger_callback("heartbeat_anomaly", {
                expected_interval = _state.heartbeat_interval,
                actual_interval = elapsed,
                anomaly = "excessive_delay"
            })
        end

        _state.last_heartbeat = now

        -- Kontrolleri çalıştır
        local results = {}
        for _, check_name in _ipairs(checks) do
            local check_func = check_map[check_name]
            if check_func then
                local ok, err_or_result = _pcall(check_func)
                if not ok then
                    log_event("heartbeat_check_error", check_name .. ": " .. _tostring(err_or_result))
                end
                results[check_name] = ok
            end
        end

        return true, results
    end

    _state.heartbeat_tick = heartbeat_tick
    log_event("heartbeat_created", "Kalp atisi sistemi olusturuldu")
    return heartbeat_tick
end

-- Kalp atışını bir kez çalıştır (manuel tetikleme)
function AntiTamper.pulse()
    if _state.heartbeat_tick then
        return _state.heartbeat_tick()
    end
    return false, "Heartbeat olusturulmamis"
end

-- Kalp atışını durdur
function AntiTamper.stop_heartbeat()
    _state.heartbeat_active = false
    log_event("heartbeat_stopped", "Kalp atisi durduruldu")
    return true
end

-- Kalp atışını yeniden başlat
function AntiTamper.resume_heartbeat()
    _state.heartbeat_active = true
    _state.last_heartbeat = get_time()
    log_event("heartbeat_resumed", "Kalp atisi yeniden baslatildi")
    return true
end

-- Coroutine tabanlı otomatik heartbeat
function AntiTamper.create_auto_heartbeat(config)
    config = config or {}
    local tick_func = AntiTamper.create_heartbeat(config)

    local co = _coroutine_wrap(function()
        while _state.heartbeat_active do
            tick_func()
            _coroutine_yield(true)
        end
        return false
    end)

    _state.heartbeat_co = co
    log_event("auto_heartbeat", "Otomatik kalp atisi olusturuldu")
    return co
end

-------------------------------------------------------------------------------
-- BÖLÜM 10: Stack Integrity (Yığın Bütünlüğü)
-------------------------------------------------------------------------------

-- Yığın canary'si oluştur
function AntiTamper.create_stack_canary(label)
    label = label or ("canary_" .. _tostring(#_state.stack_canaries + 1))

    local canary_value = generate_canary()
    local canary = {
        label    = label,
        value    = canary_value,
        hash     = compute_hash(canary_value),
        created  = _os_time(),
        verified = 0
    }

    _state.stack_canaries[label] = canary
    log_event("canary_created", label)
    return canary_value
end

-- Canary değerini doğrula
function AntiTamper.verify_canary(label, value)
    local canary = _state.stack_canaries[label]
    if not canary then
        return false, "Canary bulunamadi: " .. _tostring(label)
    end

    canary.verified = canary.verified + 1

    if canary.value ~= value then
        trigger_callback("canary_tampered", {
            label = label,
            expected = canary.hash,
            got = compute_hash(value)
        })
        return false, "Canary degistirildi: " .. label
    end

    local value_hash = compute_hash(value)
    if value_hash ~= canary.hash then
        trigger_callback("canary_hash_mismatch", {
            label = label
        })
        return false, "Canary hash uyumsuzlugu: " .. label
    end

    return true
end

-- Tüm canary'leri doğrula
function AntiTamper.verify_stack_canaries()
    local all_ok = true
    local failures = {}

    for label, canary in _pairs(_state.stack_canaries) do
        local ok, msg = AntiTamper.verify_canary(label, canary.value)
        if not ok then
            all_ok = false
            _table_insert(failures, { label = label, reason = msg })
        end
    end

    return all_ok, (not all_ok and failures or nil)
end

-- Fonksiyon çağrı derinliğini kontrol et (stack overflow koruması)
function AntiTamper.check_call_depth(max_depth)
    max_depth = max_depth or 200

    if not _debug_getinfo then
        return true
    end

    local depth = 0
    while _debug_getinfo(depth + 1, "S") do
        depth = depth + 1
        if depth > max_depth then
            trigger_callback("stack_overflow_attempt", {
                depth = depth,
                max = max_depth
            })
            return false, "Cagri derinligi asim: " .. depth
        end
    end

    return true, depth
end

-------------------------------------------------------------------------------
-- BÖLÜM 11: Upvalue Protection (Upvalue Koruma)
-------------------------------------------------------------------------------

-- Fonksiyonun upvalue'larını kaydet
function AntiTamper.register_upvalues(name, func)
    if _type(func) ~= "function" then
        _error("register_upvalues: fonksiyon bekleniyor")
    end

    if not _debug_getupvalue then
        return false, "debug.getupvalue mevcut degil"
    end

    local upvalues = {}
    local i = 1
    while true do
        local uv_name, uv_value = _debug_getupvalue(func, i)
        if uv_name == nil then break end
        upvalues[i] = {
            name  = uv_name,
            type  = _type(uv_value),
            hash  = compute_hash(_tostring(uv_value)),
            index = i
        }
        i = i + 1
    end

    _state.protected_upvalues[name] = {
        func     = func,
        upvalues = upvalues,
        count    = i - 1,
        created  = _os_time()
    }

    log_event("upvalues_registered", name .. " (" .. (i-1) .. " upvalue)")
    return true, i - 1
end

-- Upvalue'ların bütünlüğünü doğrula
function AntiTamper.verify_upvalues(name)
    local record = _state.protected_upvalues[name]
    if not record then
        return false, "Upvalue kaydi bulunamadi: " .. _tostring(name)
    end

    if not _debug_getupvalue then
        return false, "debug.getupvalue mevcut degil"
    end

    local violations = {}
    local func = record.func

    -- Upvalue sayısı kontrolü
    local current_count = 0
    local i = 1
    while true do
        local uv_name = _debug_getupvalue(func, i)
        if uv_name == nil then break end
        current_count = i
        i = i + 1
    end

    if current_count ~= record.count then
        _table_insert(violations, {
            violation = "upvalue_count_changed",
            expected = record.count,
            got = current_count
        })
    end

    -- Her upvalue'u kontrol et
    for idx, uv_info in _pairs(record.upvalues) do
        local uv_name, uv_value = _debug_getupvalue(func, idx)

        if uv_name ~= uv_info.name then
            _table_insert(violations, {
                index = idx,
                violation = "upvalue_name_changed",
                expected = uv_info.name,
                got = uv_name
            })
        end

        if _type(uv_value) ~= uv_info.type then
            _table_insert(violations, {
                index = idx,
                violation = "upvalue_type_changed",
                expected = uv_info.type,
                got = _type(uv_value)
            })
        end
    end

    if #violations > 0 then
        trigger_callback("upvalue_tampered", {
            name = name,
            violations = violations
        })
        return false, violations
    end

    return true
end

-- setupvalue'u engelle
function AntiTamper.block_setupvalue()
    if not _debug_setupvalue then return true end

    local original = _debug_setupvalue
    if debug then
        debug.setupvalue = function(func, up, value)
            -- Korunan fonksiyonları kontrol et
            for name, record in _pairs(_state.protected_upvalues) do
                if _rawequal(func, record.func) then
                    trigger_callback("setupvalue_blocked", {
                        func_name = name,
                        upvalue_index = up,
                        action = "blocked"
                    })
                    _error("Anti-tamper: Korunmus fonksiyonun upvalue'u degistirilemez - " .. name)
                end
            end
            -- Korunmayan fonksiyonlar için izin ver
            return original(func, up, value)
        end
    end

    log_event("setupvalue_blocked", "debug.setupvalue engellendi")
    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 12: String Obfuscation Helpers (Metin Gizleme Yardımcıları)
-------------------------------------------------------------------------------

-- String'i şifrele
function AntiTamper.encrypt_string(str, key)
    key = key or _state.obfuscation_key
    if key == 0 then
        key = _os_time() + _math_floor(_os_clock() * 1000)
        _state.obfuscation_key = key
    end
    return xor_string(str, _tostring(key))
end

-- String'i çöz
function AntiTamper.decrypt_string(encrypted, key)
    key = key or _state.obfuscation_key
    return xor_string(encrypted, _tostring(key))
end

-- String tablosunu şifrele (toplu)
function AntiTamper.encrypt_string_table(strings, key)
    local encrypted = {}
    for k, v in _pairs(strings) do
        if _type(v) == "string" then
            encrypted[k] = AntiTamper.encrypt_string(v, key)
        else
            encrypted[k] = v
        end
    end
    return encrypted
end

-- Güvenli string deposu oluştur
function AntiTamper.create_string_vault(key)
    key = key or _state.obfuscation_key
    if key == 0 then
        key = _os_time() + _math_floor(_os_clock() * 1000)
        _state.obfuscation_key = key
    end

    local vault = {}
    local storage = {}
    local vault_key = key

    function vault.store(name, value)
        storage[name] = AntiTamper.encrypt_string(value, vault_key)
    end

    function vault.retrieve(name)
        local encrypted = storage[name]
        if not encrypted then return nil end
        return AntiTamper.decrypt_string(encrypted, vault_key)
    end

    function vault.remove(name)
        storage[name] = nil
    end

    function vault.has(name)
        return storage[name] ~= nil
    end

    function vault.count()
        local c = 0
        for _ in _pairs(storage) do c = c + 1 end
        return c
    end

    return vault
end

-- Char tabanlı string oluşturma (statik analizi zorlaştırmak için)
function AntiTamper.build_string(byte_table)
    local chars = {}
    for i = 1, #byte_table do
        _table_insert(chars, _string_char(byte_table[i]))
    end
    return _table_concat(chars)
end

-- String'i byte tablosuna dönüştür
function AntiTamper.string_to_bytes(str)
    local bytes = {}
    for i = 1, _string_len(str) do
        _table_insert(bytes, _string_byte(str, i))
    end
    return bytes
end

-------------------------------------------------------------------------------
-- BÖLÜM 13: Module Isolation (Modül İzolasyonu)
-------------------------------------------------------------------------------

-- Güvenli require sarmalayıcı
function AntiTamper.create_safe_require(allowed_modules, denied_modules)
    allowed_modules = allowed_modules or {}
    denied_modules  = denied_modules or {}

    local allowed_map = {}
    for _, m in _ipairs(allowed_modules) do
        allowed_map[m] = true
    end

    local denied_map = {}
    for _, m in _ipairs(denied_modules) do
        denied_map[m] = true
    end

    local safe_require = function(module_name)
        -- Yasak modül kontrolü
        if denied_map[module_name] then
            trigger_callback("module_blocked", {
                module = module_name,
                action = "denied"
            })
            _error("Anti-tamper: Modul erisimi engellendi - " .. module_name)
        end

        -- Beyaz liste varsa, sadece izin verilenlere izin ver
        if _next(allowed_map) and not allowed_map[module_name] then
            trigger_callback("module_blocked", {
                module = module_name,
                action = "not_in_whitelist"
            })
            _error("Anti-tamper: Modul beyaz listede degil - " .. module_name)
        end

        -- Tehlikeli modül isimleri kontrolü
        if _string_find(module_name, "%.%.", 1, true) or
           _string_find(module_name, "/", 1, true) or
           _string_find(module_name, "\\", 1, true) then
            trigger_callback("module_path_traversal", {
                module = module_name,
                action = "blocked"
            })
            _error("Anti-tamper: Suphelsi modul yolu - " .. module_name)
        end

        local ok, result = _pcall(_require, module_name)
        if ok then
            -- Yüklenen modülün hash'ini kaydet
            if _type(result) == "table" then
                _state.module_hashes[module_name] = compute_hash(_tostring(result))
            end
            log_event("module_loaded", module_name)
            return result
        else
            _error("Modul yuklenemedi: " .. module_name .. " - " .. _tostring(result))
        end
    end

    return safe_require
end

-- Sandbox ortamı oluştur
function AntiTamper.create_sandbox(allowed_globals)
    allowed_globals = allowed_globals or {
        "print", "type", "tostring", "tonumber", "pairs", "ipairs",
        "next", "select", "unpack", "error", "pcall", "xpcall",
        "assert", "rawget", "rawset", "rawequal", "setmetatable",
        "getmetatable", "string", "table", "math", "coroutine"
    }

    local sandbox_env = {}
    local global_env = _getfenv(0)

    for _, name in _ipairs(allowed_globals) do
        local value = _rawget(global_env, name)
        if value ~= nil then
            if _type(value) == "table" then
                sandbox_env[name] = AntiTamper.make_readonly(deep_copy(value), name)
            else
                sandbox_env[name] = value
            end
        end
    end

    -- Sandbox'a özel print (opsiyonel loglama)
    local original_print = sandbox_env.print
    sandbox_env.print = function(...)
        log_event("sandbox_print", _table_concat({...}, "\t"))
        if original_print then
            original_print(...)
        end
    end

    return sandbox_env
end

-- Sandbox'ta kod çalıştır
function AntiTamper.run_in_sandbox(code, sandbox_env, name)
    sandbox_env = sandbox_env or AntiTamper.create_sandbox()
    name = name or "sandbox_chunk"

    local func, err = _loadstring(code, name)
    if not func then
        return false, "Kod derlenemedi: " .. _tostring(err)
    end

    -- Bytecode doğrulama
    local valid, valid_err = AntiTamper.validate_function_bytecode(func)
    if not valid then
        return false, "Bytecode dogrulama hatasi: " .. _tostring(valid_err)
    end

    -- Injection kontrolü
    local safe, inject_err = AntiTamper.check_bytecode_injection(func)
    if not safe then
        return false, "Bytecode injection: " .. _tostring(inject_err)
    end

    -- Sandbox ortamını ayarla
    _setfenv(func, sandbox_env)

    -- Zamanlama ile çalıştır
    local start_time = get_time()
    local ok, result = _pcall(func)
    local elapsed = get_time() - start_time

    log_event("sandbox_execution", _string_format("%s (%.4fs)", name, elapsed))

    if not ok then
        return false, "Calisma hatasi: " .. _tostring(result)
    end

    return true, result, elapsed
end

-------------------------------------------------------------------------------
-- BÖLÜM 14: Timing Attack Detection (Zamanlama Saldırı Tespiti)
-------------------------------------------------------------------------------

-- Zamanlama ölçümü başlat
function AntiTamper.start_timing(label)
    label = label or "default"
    _state.execution_tokens[label] = {
        start = get_time(),
        checkpoints = {},
        finished = false
    }
    return true
end

-- Zamanlama kontrol noktası ekle
function AntiTamper.timing_checkpoint(label, checkpoint_name)
    local token = _state.execution_tokens[label]
    if not token then
        return false, "Zamanlama tokeni bulunamadi"
    end

    local now = get_time()
    _table_insert(token.checkpoints, {
        name = checkpoint_name or ("#" .. (#token.checkpoints + 1)),
        time = now,
        elapsed = now - token.start
    })
    return true
end

-- Zamanlama ölçümünü bitir ve anomali kontrol et
function AntiTamper.end_timing(label, expected_min, expected_max)
    local token = _state.execution_tokens[label]
    if not token then
        return false, "Zamanlama tokeni bulunamadi"
    end

    local now = get_time()
    local total_elapsed = now - token.start
    token.finished = true
    token.total = total_elapsed

    -- Anomali kontrolü
    if expected_min and total_elapsed < expected_min then
        trigger_callback("timing_anomaly", {
            label = label,
            elapsed = total_elapsed,
            expected_min = expected_min,
            anomaly = "too_fast"
        })
        return false, "Cok hizli yurutme (debug/skip suphelisi)"
    end

    if expected_max and total_elapsed > expected_max then
        trigger_callback("timing_anomaly", {
            label = label,
            elapsed = total_elapsed,
            expected_max = expected_max,
            anomaly = "too_slow"
        })
        return false, "Cok yavas yurutme (breakpoint/attach suphelisi)"
    end

    return true, total_elapsed
end

-- Anlık zamanlama saldırısı kontrolü
function AntiTamper.check_timing_attack()
    local iterations = 1000
    local start = get_time()
    local dummy = 0
    for i = 1, iterations do
        dummy = dummy + i
    end
    local elapsed = get_time() - start

    -- Normal koşullarda bu döngü çok hızlı bitmeli
    if elapsed > _state.timing_threshold then
        trigger_callback("timing_attack", {
            elapsed = elapsed,
            threshold = _state.timing_threshold,
            iterations = iterations,
            anomaly = "suspicious_slowdown"
        })
        return false, "Zamanlama anomalisi tespit edildi"
    end

    return true, elapsed
end

-------------------------------------------------------------------------------
-- BÖLÜM 15: Digital Watermarking (Dijital Filigran)
-------------------------------------------------------------------------------

-- Dijital filigran oluştur
function AntiTamper.create_watermark(data)
    local timestamp = _os_time()
    local clock = _os_clock()

    local watermark = {
        data      = data or "protected",
        timestamp = timestamp,
        hash      = compute_dual_hash(data .. _tostring(timestamp) .. _tostring(clock)),
        signature = compute_hash_fnv(data .. _tostring(timestamp)),
        version   = "1.0"
    }

    _table_insert(_state.watermarks, watermark)
    log_event("watermark_created", watermark.hash)
    return watermark
end

-- Filigranı doğrula
function AntiTamper.verify_watermark(watermark)
    if _type(watermark) ~= "table" then
        return false, "Gecersiz filigran"
    end

    -- Hash yeniden hesapla ve doğrula
    local expected_hash = compute_dual_hash(
        watermark.data .. _tostring(watermark.timestamp) .. _tostring(_os_clock())
    )

    -- Signature kontrolü
    local expected_sig = compute_hash_fnv(
        watermark.data .. _tostring(watermark.timestamp)
    )

    if watermark.signature ~= expected_sig then
        trigger_callback("watermark_tampered", {
            expected_sig = expected_sig,
            got_sig = watermark.signature
        })
        return false, "Filigran imzasi bozulmus"
    end

    return true
end

-- Fonksiyona filigran göm
function AntiTamper.embed_watermark(func, watermark_data)
    if _type(func) ~= "function" then
        _error("embed_watermark: fonksiyon bekleniyor")
    end

    local watermark = AntiTamper.create_watermark(watermark_data)
    local func_hash = compute_function_hash(func)

    local watermarked = function(...)
        -- Filigran doğrulama (her çağrıda)
        if not AntiTamper.verify_watermark(watermark) then
            trigger_callback("watermarked_func_tampered", {
                watermark = watermark,
                func_hash = func_hash
            })
        end
        return func(...)
    end

    return watermarked, watermark
end

-------------------------------------------------------------------------------
-- BÖLÜM 16: System Fingerprinting (Sistem Parmak İzi)
-------------------------------------------------------------------------------

-- Sistem parmak izi oluştur
function AntiTamper.create_fingerprint()
    local parts = {
        _VERSION,
        _tostring(collectgarbage),
        _tostring(math.pi),
        _tostring(math.huge),
        _tostring(2^53),
        _tostring(#_state.integrity_map),
        _tostring(_os_time()),
    }

    local fp = compute_dual_hash(_table_concat(parts, "|"))
    _state.fingerprint = fp
    log_event("fingerprint_created", fp)
    return fp
end

-- Parmak izini doğrula (aynı ortamda olup olmadığımızı kontrol et)
function AntiTamper.verify_fingerprint()
    if _state.fingerprint == "" then
        return false, "Parmak izi olusturulmamis"
    end

    -- Kritik çevre değişkenlerini kontrol et
    if _VERSION ~= "Lua 5.1" then
        trigger_callback("fingerprint_mismatch", {
            component = "_VERSION",
            expected = "Lua 5.1",
            got = _VERSION
        })
        return false, "Lua versiyonu degisti"
    end

    return true
end

-------------------------------------------------------------------------------
-- BÖLÜM 17: Loadstring / Load Protection (Yükleme Koruması)
-------------------------------------------------------------------------------

-- Güvenli loadstring sarmalayıcı
function AntiTamper.create_safe_loadstring(config)
    config = config or {}
    local max_size     = config.max_size or 1024 * 1024  -- 1MB
    local allowed      = config.allowed_patterns or {}
    local blocked      = config.blocked_patterns or {
        "debug%.",
        "os%.execute",
        "os%.remove",
        "os%.rename",
        "io%.open",
        "io%.popen",
        "loadfile",
        "dofile",
        "rawset.*_G",
        "getfenv",
        "setfenv",
    }
    local sandbox_env  = config.sandbox_env or nil

    return function(code, chunk_name)
        if _type(code) ~= "string" then
            return nil, "String bekleniyor"
        end

        -- Boyut kontrolü
        if _string_len(code) > max_size then
            trigger_callback("loadstring_size_exceeded", {
                size = _string_len(code),
                max = max_size
            })
            return nil, "Kod boyutu siniri asildi"
        end

        -- Yasaklı pattern kontrolü
        for _, pattern in _ipairs(blocked) do
            if _string_find(code, pattern) then
                trigger_callback("loadstring_blocked_pattern", {
                    pattern = pattern,
                    action = "blocked"
                })
                return nil, "Yasakli pattern tespit edildi: " .. pattern
            end
        end

        -- İzin verilen pattern kontrolü (eğer liste boş değilse)
        if #allowed > 0 then
            local has_allowed = false
            for _, pattern in _ipairs(allowed) do
                if _string_find(code, pattern) then
                    has_allowed = true
                    break
                end
            end
            if not has_allowed then
                return nil, "Izin verilen pattern bulunamadi"
            end
        end

        -- Derle
        local func, err = _loadstring(code, chunk_name or "safe_chunk")
        if not func then
            return nil, err
        end

        -- Bytecode doğrulama
        local valid, valid_err = AntiTamper.validate_function_bytecode(func)
        if not valid then
            return nil, "Bytecode dogrulama: " .. _tostring(valid_err)
        end

        -- Sandbox ortamını ayarla
        if sandbox_env then
            _setfenv(func, sandbox_env)
        end

        log_event("safe_loadstring", chunk_name or "anonymous")
        return func
    end
end

-------------------------------------------------------------------------------
-- BÖLÜM 18: Execution Token System (Yürütme Token Sistemi)
-------------------------------------------------------------------------------

-- Yürütme tokeni oluştur
function AntiTamper.create_execution_token(name, ttl)
    ttl = ttl or 60 -- 60 saniye varsayılan ömür

    local token = {
        name     = name,
        value    = generate_canary(),
        created  = _os_time(),
        ttl      = ttl,
        expired  = false,
        used     = false,
        hash     = nil
    }
    token.hash = compute_hash(token.value .. _tostring(token.created))

    _state.execution_tokens[name] = token
    log_event("token_created", name)
    return token.value
end

-- Token'ı doğrula
function AntiTamper.validate_execution_token(name, value)
    local token = _state.execution_tokens[name]
    if not token or _type(token) ~= "table" or not token.created then
        return false, "Token bulunamadi"
    end

    -- TTL kontrolü
    local age = _os_difftime(_os_time(), token.created)
    if age > token.ttl then
        token.expired = true
        trigger_callback("token_expired", {
            name = name,
            age = age,
            ttl = token.ttl
        })
        return false, "Token suresi dolmus"
    end

    -- Değer kontrolü
    if token.value ~= value then
        trigger_callback("token_invalid", {
            name = name,
            action = "value_mismatch"
        })
        return false, "Gecersiz token degeri"
    end

    -- Hash kontrolü
    local expected_hash = compute_hash(value .. _tostring(token.created))
    if expected_hash ~= token.hash then
        trigger_callback("token_hash_mismatch", {
            name = name,
            action = "hash_tampered"
        })
        return false, "Token hash'i bozulmus"
    end

    token.used = true
    return true
end

-- Tek kullanımlık token
function AntiTamper.create_one_time_token(name)
    local value = AntiTamper.create_execution_token(name, 300)

    local validate_once = function(provided_value)
        local token = _state.execution_tokens[name]
        if token and _type(token) == "table" and token.used then
            trigger_callback("token_reuse_attempt", {
                name = name,
                action = "blocked"
            })
            return false, "Token zaten kullanildi"
        end

        return AntiTamper.validate_execution_token(name, provided_value)
    end

    return value, validate_once
end

-------------------------------------------------------------------------------
-- BÖLÜM 19: Callback Management (Geri Çağırma Yönetimi)
-------------------------------------------------------------------------------

-- Olay geri çağırması ekle
function AntiTamper.on(event_type, callback)
    if _type(callback) ~= "function" then
        _error("on: fonksiyon bekleniyor")
    end

    if not _state.callbacks[event_type] then
        _state.callbacks[event_type] = {}
    end

    _table_insert(_state.callbacks[event_type], callback)
    log_event("callback_registered", event_type)
    return #_state.callbacks[event_type]
end

-- Olay geri çağırmasını kaldır
function AntiTamper.off(event_type, index)
    if _state.callbacks[event_type] and _state.callbacks[event_type][index] then
        _table_remove(_state.callbacks[event_type], index)
        log_event("callback_removed", event_type .. "#" .. _tostring(index))
        return true
    end
    return false
end

-- Tüm geri çağırmaları temizle
function AntiTamper.clear_callbacks(event_type)
    if event_type then
        _state.callbacks[event_type] = nil
    else
        _state.callbacks = {}
    end
    log_event("callbacks_cleared", event_type or "all")
    return true
end

-- Desteklenen olay tiplerini listele
function AntiTamper.list_event_types()
    return {
        "tamper",                   -- Genel tamper olayı
        "critical",                 -- Kritik ihlal limiti
        "env_violation",            -- Ortam ihlali
        "env_write_blocked",        -- Ortam yazma engeli
        "function_tampered",        -- Fonksiyon değiştirildi
        "function_replaced",        -- Fonksiyon referansı değişti
        "protected_call_blocked",   -- Korumalı çağrı engeli
        "runtime_integrity",        -- Çalışma zamanı bütünlüğü
        "library_tamper",           -- Kütüphane değişikliği
        "hook_detected",            -- Hook tespit edildi
        "debug_access_blocked",     -- Debug erişimi engeli
        "debug_getupvalue_attempt", -- Upvalue okuma denemesi
        "readonly_violation",       -- Salt okunur ihlali
        "deep_readonly_violation",  -- Derin salt okunur ihlali
        "metatable_tamper",         -- Metatable değişikliği
        "heartbeat_anomaly",        -- Kalp atışı anomalisi
        "canary_tampered",          -- Canary değiştirildi
        "canary_hash_mismatch",     -- Canary hash uyumsuzluğu
        "stack_overflow_attempt",   -- Yığın taşması denemesi
        "upvalue_tampered",         -- Upvalue değiştirildi
        "setupvalue_blocked",       -- setupvalue engeli
        "module_blocked",           -- Modül erişimi engeli
        "module_path_traversal",    -- Path traversal denemesi
        "timing_anomaly",           -- Zamanlama anomalisi
        "timing_attack",            -- Zamanlama saldırısı
        "watermark_tampered",       -- Filigran bozuldu
        "watermarked_func_tampered",-- Filigranlı fonksiyon bozuldu
        "fingerprint_mismatch",     -- Parmak izi uyumsuzluğu
        "loadstring_size_exceeded", -- Loadstring boyut aşımı
        "loadstring_blocked_pattern", -- Yasaklı pattern
        "token_expired",            -- Token süresi doldu
        "token_invalid",            -- Geçersiz token
        "token_hash_mismatch",      -- Token hash uyumsuzluğu
        "token_reuse_attempt",      -- Token yeniden kullanım
        "bytecode_injection",       -- Bytecode injection
        "callback_error",           -- Callback hatası
        "sandbox_print",            -- Sandbox print
    }
end

-------------------------------------------------------------------------------
-- BÖLÜM 20: Configuration & Initialization (Yapılandırma & Başlatma)
-------------------------------------------------------------------------------

-- Tam yapılandırma ile başlat
function AntiTamper.init(config)
    if _state.initialized then
        return false, "Zaten baslatildi"
    end

    config = config or {}

    -- Rastgele tohum ayarla
    _math_randomseed(_os_time() + _math_floor(_os_clock() * 10000))

    -- Checksum tohum
    _state.checksum_seed = config.checksum_seed or generate_canary()

    -- Obfuscation key
    _state.obfuscation_key = config.obfuscation_key or generate_canary()

    -- Maksimum ihlal
    _state.max_violations = config.max_violations or 5

    -- Zamanlama eşiği
    _state.timing_threshold = config.timing_threshold or 0.05

    -- Günlük boyutu
    _state.log_max = config.log_max or 1000

    -- Kalp atışı aralığı
    _state.heartbeat_interval = config.heartbeat_interval or 0.1

    -- Parmak izi oluştur
    AntiTamper.create_fingerprint()

    -- Ortam görüntüsünü al
    if config.snapshot_env ~= false then
        AntiTamper.snapshot_environment()
    end

    -- Debug kütüphanesini kilitle
    if config.lock_debug ~= false then
        AntiTamper.lock_debug_library()
    end

    -- Hook kontrolü
    if config.check_hooks ~= false then
        AntiTamper.check_hooks()
        AntiTamper.clear_hooks()
    end

    -- Hook tuzağı kur
    if config.hook_traps ~= false then
        AntiTamper.set_hook_trap()
    end

    -- Stack canary oluştur
    if config.create_canaries ~= false then
        for i = 1, (config.canary_count or 3) do
            AntiTamper.create_stack_canary("init_canary_" .. i)
        end
    end

    -- setupvalue engelle
    if config.block_setupvalue ~= false then
        AntiTamper.block_setupvalue()
    end

    -- Heartbeat oluştur
    if config.heartbeat ~= false then
        AntiTamper.create_heartbeat(config.heartbeat_config)
    end

    -- Filigran oluştur
    if config.watermark then
        AntiTamper.create_watermark(config.watermark)
    end

    _state.initialized = true
    log_event("initialized", "Anti-tamper sistemi baslatildi")

    return true
end

-- Durumu sıfırla (test amaçlı)
function AntiTamper.reset()
    _state.initialized       = false
    _state.integrity_map     = {}
    _state.protected_tables  = {}
    _state.protected_funcs   = {}
    _state.env_snapshot      = {}
    _state.callbacks         = {}
    _state.heartbeat_active  = false
    _state.heartbeat_co      = nil
    _state.heartbeat_tick    = nil
    _state.last_heartbeat    = 0
    _state.violation_count   = 0
    _state.tamper_detected   = false
    _state.stack_canaries    = {}
    _state.protected_upvalues = {}
    _state.module_hashes     = {}
    _state.execution_tokens  = {}
    _state.debug_locked      = false
    _state.env_locked        = false
    _state.hook_traps        = {}
    _state.watermarks        = {}
    _state.log               = {}
    _state.fingerprint       = ""

    log_event("reset", "Sistem sifirlandi")
    return true
end

-- Durum raporu al
function AntiTamper.get_status()
    return {
        initialized       = _state.initialized,
        debug_locked      = _state.debug_locked,
        env_locked        = _state.env_locked,
        heartbeat_active  = _state.heartbeat_active,
        violation_count   = _state.violation_count,
        max_violations    = _state.max_violations,
        tamper_detected   = _state.tamper_detected,
        registered_funcs  = (function()
            local c = 0
            for _ in _pairs(_state.integrity_map) do c = c + 1 end
            return c
        end)(),
        protected_tables  = (function()
            local c = 0
            for _ in _pairs(_state.protected_tables) do c = c + 1 end
            return c
        end)(),
        canary_count      = (function()
            local c = 0
            for _ in _pairs(_state.stack_canaries) do c = c + 1 end
            return c
        end)(),
        watermark_count   = #_state.watermarks,
        log_entries       = #_state.log,
        fingerprint       = _state.fingerprint,
    }
end

-- Günlüğü al
function AntiTamper.get_log(last_n)
    if last_n then
        local result = {}
        local start = _math_max(1, #_state.log - last_n + 1)
        for i = start, #_state.log do
            _table_insert(result, _state.log[i])
        end
        return result
    end
    return _state.log
end

-- Kapsamlı bütünlük taraması
function AntiTamper.full_scan()
    local results = {
        timestamp = _os_time(),
        checks    = {},
        passed    = 0,
        failed    = 0,
        total     = 0
    }

    local checks = {
        { name = "Runtime Integrity",     func = AntiTamper.verify_runtime_integrity },
        { name = "Standard Libraries",    func = AntiTamper.verify_standard_libraries },
        { name = "Environment",           func = AntiTamper.verify_environment },
        { name = "Registered Functions",  func = AntiTamper.verify_all_functions },
        { name = "Protected Tables",      func = AntiTamper.verify_protected_tables },
        { name = "Stack Canaries",        func = AntiTamper.verify_stack_canaries },
        { name = "Hooks",                 func = AntiTamper.check_hooks },
        { name = "Hook Traps",            func = AntiTamper.run_hook_traps },
        { name = "Timing",               func = AntiTamper.check_timing_attack },
        { name = "Fingerprint",           func = AntiTamper.verify_fingerprint },
    }

    for _, check in _ipairs(checks) do
        local ok, result = _pcall(check.func)
        results.total = results.total + 1

        if ok and result then
            results.passed = results.passed + 1
            results.checks[check.name] = { passed = true }
        else
            results.failed = results.failed + 1
            results.checks[check.name] = { passed = false, error = _tostring(result) }
        end
    end

    results.integrity_score = _math_floor((results.passed / results.total) * 100)

    log_event("full_scan", _string_format(
        "Sonuc: %d/%d gecti (%%%d)",
        results.passed, results.total, results.integrity_score
    ))

    return results
end

-- Hızlı bütünlük kontrolü (performans odaklı)
function AntiTamper.quick_check()
    -- Sadece en kritik kontrolleri yap
    local ok1 = AntiTamper.verify_runtime_integrity()
    local ok2 = AntiTamper.check_hooks()
    local ok3 = AntiTamper.verify_stack_canaries()

    return ok1 and ok2 and ok3
end

-------------------------------------------------------------------------------
-- BÖLÜM 21: Anti-Tamper Guard (Otomatik Koruma Döngüsü)
-------------------------------------------------------------------------------

-- Koruma döngüsü oluştur (coroutine tabanlı)
function AntiTamper.create_guard(config)
    config = config or {}

    local check_interval = config.interval or 1.0 -- saniye
    local on_tamper      = config.on_tamper or function(results)
        _error("Anti-tamper: Butunluk ihlali tespit edildi!")
    end
    local checks         = config.checks or { "quick" }

    local guard = {}
    guard.active = true
    guard.check_count = 0
    guard.last_check = get_time()

    function guard.tick()
        if not guard.active then return true end

        local now = get_time()
        if (now - guard.last_check) < check_interval then
            return true -- Henüz kontrol zamanı gelmedi
        end

        guard.last_check = now
        guard.check_count = guard.check_count + 1

        local all_ok = true
        local failures = {}

        for _, check_name in _ipairs(checks) do
            local ok, result
            if check_name == "quick" then
                ok = AntiTamper.quick_check()
            elseif check_name == "full" then
                local scan = AntiTamper.full_scan()
                ok = scan.failed == 0
                result = scan
            elseif check_name == "runtime" then
                ok = AntiTamper.verify_runtime_integrity()
            elseif check_name == "hooks" then
                ok = AntiTamper.check_hooks()
            elseif check_name == "canaries" then
                ok = AntiTamper.verify_stack_canaries()
            elseif check_name == "environment" then
                ok = AntiTamper.verify_environment()
            elseif check_name == "timing" then
                ok = AntiTamper.check_timing_attack()
            elseif check_name == "heartbeat" then
                ok = AntiTamper.pulse()
            end

            if not ok then
                all_ok = false
                _table_insert(failures, {
                    check = check_name,
                    result = result
                })
            end
        end

        if not all_ok then
            on_tamper(failures)
        end

        return all_ok
    end

    function guard.stop()
        guard.active = false
    end

    function guard.start()
        guard.active = true
        guard.last_check = get_time()
    end

    function guard.get_stats()
        return {
            active = guard.active,
            check_count = guard.check_count,
            last_check = guard.last_check
        }
    end

    log_event("guard_created", "Koruma noktasi olusturuldu")
    return guard
end

-------------------------------------------------------------------------------
-- Modülü dışa aktar
-------------------------------------------------------------------------------

-- AntiTamper modülünü kendi kendine koru
AntiTamper._VERSION = "2.0.0"
AntiTamper._DESCRIPTION = "Lua 5.1 Anti-Tamper Protection System"

return AntiTamper
