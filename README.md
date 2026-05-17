# Anti-Tamper Protection System - Lua 5.1

Lua 5.1 ile tam uyumlu, kapsamlı ve gelişmiş anti-tamper koruma sistemi. Harici bağımlılık gerektirmez.

## Özellikler

| Modül | Açıklama |
|-------|----------|
| **Environment Protection** | Global ortam değişikliklerini algılar ve engeller |
| **Function Integrity** | Fonksiyon bytecode hash'leri ile bütünlük doğrulaması |
| **Debug Library Lockdown** | Debug kütüphanesini kilitler veya tamamen kaldırır |
| **Bytecode Validation** | Lua 5.1 bytecode header ve injection kontrolü |
| **Runtime Integrity** | Kritik Lua fonksiyonlarının değiştirilmediğini doğrular |
| **Anti-Hook** | Debug hook'ları tespit eder ve temizler |
| **Metatable Protection** | Tabloları salt okunur yapar, metatable değişikliklerini engeller |
| **Heartbeat System** | Periyodik bütünlük kontrolleri ile sürekli izleme |
| **Stack Canaries** | Yığın bütünlüğünü canary değerleri ile korur |
| **Upvalue Protection** | Fonksiyon upvalue'larını izler ve korur |
| **String Obfuscation** | XOR şifreleme, güvenli string deposu (vault) |
| **Module Isolation** | Güvenli require, sandbox ortamı |
| **Timing Attack Detection** | Zamanlama anomalilerini tespit eder |
| **Digital Watermarking** | Dijital filigran oluşturma ve doğrulama |
| **Execution Tokens** | TTL'li, tek kullanımlık yürütme tokenları |
| **Guard System** | Otomatik koruma döngüsü |
| **Callback System** | 30+ olay tipi için geri çağırma desteği |

## Hızlı Başlangıç

```lua
local AntiTamper = require("anti_tamper")

-- Tamper olaylarını dinle
AntiTamper.on("tamper", function(event_type, info)
    print("TAMPER: " .. event_type)
end)

-- Sistemi başlat (tüm korumalar aktif)
AntiTamper.init()

-- Kritik fonksiyonları koru
local function benim_fonksiyonum(x)
    return x * 2
end

local korunmus = AntiTamper.protect_function("benim_fonk", benim_fonksiyonum)
print(korunmus(21)) -- 42

-- Periyodik kontrol
local ok = AntiTamper.quick_check()
print("Sistem butun mu: " .. tostring(ok))
```

## Detaylı Kullanım

### Başlatma Seçenekleri

```lua
AntiTamper.init({
    max_violations     = 10,        -- Maks ihlal sayısı
    timing_threshold   = 0.05,      -- Zamanlama eşiği (saniye)
    lock_debug         = true,      -- Debug kütüphanesini kilitle
    check_hooks        = true,      -- Hook kontrolü yap
    hook_traps         = true,      -- Hook tuzakları kur
    canary_count       = 5,         -- Stack canary sayısı
    block_setupvalue   = true,      -- setupvalue engelle
    heartbeat          = true,      -- Heartbeat aktif
    watermark          = "App_v1",  -- Dijital filigran
    snapshot_env       = true,      -- Ortam görüntüsü al
    log_max            = 1000,      -- Maks günlük girişi
})
```

### Fonksiyon Koruma

```lua
-- Tek fonksiyon kaydet
AntiTamper.register_function("onemli_func", my_func)

-- Toplu kayıt
AntiTamper.register_functions({
    func1 = my_func1,
    func2 = my_func2,
})

-- Korumalı sarmalayıcı (her çağrıda bütünlük kontrolü)
local protected = AntiTamper.protect_function("kritik", my_func)

-- Doğrulama
local ok, msg = AntiTamper.verify_function("onemli_func")
local all_ok, failures = AntiTamper.verify_all_functions()
```

### Salt Okunur Tablolar

```lua
-- Basit salt okunur
local cfg = AntiTamper.make_readonly({ key = "value" }, "config")
cfg.key = "hack" -- HATA: yazma engellenir

-- Derin salt okunur (iç içe tablolar dahil)
local deep = AntiTamper.make_deep_readonly({
    db = { host = "localhost", port = 5432 }
}, "app_config")
deep.db.host = "evil" -- HATA: engellenir
```

### String Şifreleme

```lua
-- Basit şifreleme
local enc = AntiTamper.encrypt_string("gizli mesaj")
local dec = AntiTamper.decrypt_string(enc)

-- Güvenli depo (vault)
local vault = AntiTamper.create_string_vault()
vault.store("api_key", "sk-xxxxx")
local key = vault.retrieve("api_key")

-- Statik analizi zorlaştır
local s = AntiTamper.build_string({72, 101, 108, 108, 111}) -- "Hello"
```

### Sandbox

```lua
-- Güvenli ortamda kod çalıştır
local ok, result = AntiTamper.run_in_sandbox([[
    return 2 + 2
]])

-- Tehlikeli kodlar otomatik engellenir
local ok, err = AntiTamper.run_in_sandbox([[
    os.execute("rm -rf /") -- bu çalışmaz
]])
```

### Güvenli Loadstring

```lua
local safe_load = AntiTamper.create_safe_loadstring({
    max_size = 10000,
    blocked_patterns = { "os%.execute", "io%.open", "debug%." },
})

local func = safe_load("return 42")  -- OK
local func = safe_load('os.execute("whoami")') -- nil, engellendi
```

### Heartbeat & Guard

```lua
-- Manuel pulse
local ok, results = AntiTamper.pulse()

-- Otomatik guard
local guard = AntiTamper.create_guard({
    interval = 1.0,
    checks = { "quick" },
    on_tamper = function(failures)
        print("TAMPER!")
    end
})

-- Oyun/uygulama döngüsünde çağır
while running do
    guard.tick()
    -- ... uygulama kodu ...
end
```

### Olay Sistemi

```lua
-- Olay dinle
AntiTamper.on("function_tampered", function(event, info)
    print("Fonksiyon degistirildi: " .. info.name)
end)

AntiTamper.on("hook_detected", function(event, info)
    print("Hook tespit edildi!")
end)

-- Desteklenen 30+ olay tipi
local events = AntiTamper.list_event_types()
```

### Tam Tarama

```lua
local scan = AntiTamper.full_scan()
print("Skor: %" .. scan.integrity_score)

for name, result in pairs(scan.checks) do
    print(name .. ": " .. (result.passed and "OK" or "FAIL"))
end
```

## Mimari

```
┌─────────────────────────────────────────────────────────┐
│                    AntiTamper.init()                     │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│ Env      │ Function │ Debug    │ Bytecode │ Runtime      │
│ Protect  │ Integrity│ Lockdown │ Validate │ Integrity    │
├──────────┼──────────┼──────────┼──────────┼──────────────┤
│ Anti-    │ Meta-    │ Heart-   │ Stack    │ Upvalue      │
│ Hook     │ table    │ beat     │ Canary   │ Protection   │
├──────────┼──────────┼──────────┼──────────┼──────────────┤
│ String   │ Module   │ Timing   │ Water-   │ Execution    │
│ Obfusc.  │ Isolate  │ Detect   │ mark     │ Tokens       │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│              Callback & Event System                     │
│              Guard (Auto Protection Loop)                │
│              Logging & Status Reporting                  │
└─────────────────────────────────────────────────────────┘
```

## Lisans

MIT
