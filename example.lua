--[[
    Anti-Tamper Kullanım Örneği
    Lua 5.1 Uyumlu

    Bu dosya, anti_tamper modülünün tüm özelliklerinin
    nasıl kullanılacağını gösterir.
--]]

local AntiTamper = require("anti_tamper")

print("=" .. string.rep("=", 68))
print("  ANTI-TAMPER KORUMA SİSTEMİ - KULLANIM ÖRNEĞİ")
print("=" .. string.rep("=", 68))
print()

-------------------------------------------------------------------------------
-- 1) Callback Kayıtları (Olayları dinleme)
-------------------------------------------------------------------------------
print("[1] Callback kayitlari yapiliyor...")

-- Genel tamper olayı
AntiTamper.on("tamper", function(event_type, info)
    print("  [!] TAMPER ALGILANDI: " .. tostring(event_type))
    if type(info) == "table" then
        for k, v in pairs(info) do
            print("      " .. tostring(k) .. " = " .. tostring(v))
        end
    else
        print("      Detay: " .. tostring(info))
    end
end)

-- Kritik ihlal limiti
AntiTamper.on("critical", function(event_type, info)
    print("  [!!!] KRITIK: " .. tostring(info))
end)

-- Ortam ihlali
AntiTamper.on("env_violation", function(event_type, info)
    print("  [ENV] Ortam ihlali: " .. tostring(info.key or info))
end)

-- Hook tespiti
AntiTamper.on("hook_detected", function(event_type, info)
    print("  [HOOK] Hook tespit edildi!")
end)

-- Zamanlama anomalisi
AntiTamper.on("timing_anomaly", function(event_type, info)
    print("  [TIMING] Zamanlama anomalisi!")
end)

print("  Callback'ler kaydedildi.\n")

-------------------------------------------------------------------------------
-- 2) Sistemi Başlat
-------------------------------------------------------------------------------
print("[2] Anti-tamper sistemi baslatiliyor...")

local ok, err = AntiTamper.init({
    max_violations     = 10,
    timing_threshold   = 0.1,
    lock_debug         = true,
    check_hooks        = true,
    hook_traps         = true,
    canary_count       = 5,
    block_setupvalue   = true,
    heartbeat          = true,
    watermark          = "MyApp_v1.0",
    heartbeat_config   = {
        interval = 0.5,
        checks   = { "runtime_integrity", "hooks", "stack_canaries" }
    }
})

if ok then
    print("  Sistem basariyla baslatildi.\n")
else
    print("  Baslama hatasi: " .. tostring(err) .. "\n")
end

-------------------------------------------------------------------------------
-- 3) Durum Raporu
-------------------------------------------------------------------------------
print("[3] Durum raporu:")
local status = AntiTamper.get_status()
for k, v in pairs(status) do
    print("  " .. tostring(k) .. " = " .. tostring(v))
end
print()

-------------------------------------------------------------------------------
-- 4) Fonksiyon Koruma
-------------------------------------------------------------------------------
print("[4] Fonksiyon koruma ornekleri...")

-- Kritik bir fonksiyon tanımla
local function hesapla_toplam(a, b)
    return a + b
end

local function sifre_kontrol(girdi, beklenen)
    return girdi == beklenen
end

-- Fonksiyonları kaydet
AntiTamper.register_function("hesapla_toplam", hesapla_toplam)
AntiTamper.register_function("sifre_kontrol", sifre_kontrol)
print("  Fonksiyonlar kaydedildi.")

-- Bütünlük doğrulama
local intact, msg = AntiTamper.verify_function("hesapla_toplam", hesapla_toplam)
print("  hesapla_toplam butunlugu: " .. tostring(intact))

-- Korumalı fonksiyon oluştur
local guvenli_hesapla = AntiTamper.protect_function("guvenli_hesapla", hesapla_toplam)
local sonuc = guvenli_hesapla(3, 5)
print("  guvenli_hesapla(3, 5) = " .. tostring(sonuc))

-- Toplu kayıt
local fonksiyonlar = {
    math_floor = math.floor,
    math_ceil  = math.ceil,
    math_abs   = math.abs,
}
AntiTamper.register_functions(fonksiyonlar)
print("  Toplu fonksiyon kaydi tamamlandi.")

-- Tüm fonksiyonları doğrula
local all_ok, failures = AntiTamper.verify_all_functions()
print("  Tum fonksiyonlar butun mu: " .. tostring(all_ok))
if not all_ok then
    for _, f in ipairs(failures) do
        print("    Hata: " .. f.name .. " - " .. f.reason)
    end
end
print()

-------------------------------------------------------------------------------
-- 5) Metatable Koruma
-------------------------------------------------------------------------------
print("[5] Metatable koruma ornekleri...")

-- Salt okunur tablo
local config = { host = "localhost", port = 8080, debug = false }
local readonly_config = AntiTamper.make_readonly(config, "app_config")

print("  readonly_config.host = " .. tostring(readonly_config.host))
print("  readonly_config.port = " .. tostring(readonly_config.port))

-- Yazma denemesi (engellenecek)
local write_ok = pcall(function()
    readonly_config.host = "hacked.com"
end)
print("  Yazma denemesi basarili mi: " .. tostring(write_ok) .. " (false olmali)")

-- Derin salt okunur
local nested = {
    server = { host = "localhost", port = 8080 },
    db     = { host = "db.local",  port = 5432 },
}
local deep_ro = AntiTamper.make_deep_readonly(nested, "nested_config")
print("  deep_ro.server.host = " .. tostring(deep_ro.server.host))

local deep_write_ok = pcall(function()
    deep_ro.server.host = "evil.com"
end)
print("  Derin yazma denemesi basarili mi: " .. tostring(deep_write_ok) .. " (false olmali)")
print()

-------------------------------------------------------------------------------
-- 6) String Şifreleme
-------------------------------------------------------------------------------
print("[6] String sifreleme ornekleri...")

local orijinal = "Bu cok gizli bir mesajdir!"
local sifrelenmis = AntiTamper.encrypt_string(orijinal)
local cozulmus = AntiTamper.decrypt_string(sifrelenmis)

print("  Orijinal:    " .. orijinal)
print("  Sifrelenmis: (binary, " .. #sifrelenmis .. " byte)")
print("  Cozulmus:    " .. cozulmus)
print("  Eslesme:     " .. tostring(orijinal == cozulmus))

-- String vault (güvenli depo)
local vault = AntiTamper.create_string_vault()
vault.store("api_key", "sk-1234567890abcdef")
vault.store("db_pass", "super_secret_123")

print("  Vault'tan api_key: " .. vault.retrieve("api_key"))
print("  Vault'ta db_pass var mi: " .. tostring(vault.has("db_pass")))
print("  Vault eleman sayisi: " .. vault.count())

-- Byte tabanlı string oluşturma
local hidden = AntiTamper.build_string({72, 101, 108, 108, 111}) -- "Hello"
print("  Byte'lardan string: " .. hidden)
print()

-------------------------------------------------------------------------------
-- 7) Bytecode Doğrulama
-------------------------------------------------------------------------------
print("[7] Bytecode dogrulama ornekleri...")

local test_func = function(x) return x * 2 end
local bc_valid, bc_msg = AntiTamper.validate_function_bytecode(test_func)
print("  test_func bytecode gecerli mi: " .. tostring(bc_valid) .. " - " .. tostring(bc_msg))

local inject_safe, inject_msg = AntiTamper.check_bytecode_injection(test_func)
print("  Injection kontrolu: " .. tostring(inject_safe) .. " - " .. tostring(inject_msg or "temiz"))
print()

-------------------------------------------------------------------------------
-- 8) Sandbox
-------------------------------------------------------------------------------
print("[8] Sandbox ornekleri...")

local sandbox = AntiTamper.create_sandbox()
local s_ok, s_result = AntiTamper.run_in_sandbox([[
    local x = 10
    local y = 20
    return x + y
]], sandbox, "test_sandbox")

print("  Sandbox calistirma basarili mi: " .. tostring(s_ok))
print("  Sonuc: " .. tostring(s_result))

-- Tehlikeli kod denemesi
local d_ok, d_result = AntiTamper.run_in_sandbox([[
    os.execute("rm -rf /")
]], sandbox, "dangerous_sandbox")
print("  Tehlikeli kod basarili mi: " .. tostring(d_ok) .. " (false olmali)")
print("  Hata: " .. tostring(d_result))
print()

-------------------------------------------------------------------------------
-- 9) Güvenli Loadstring
-------------------------------------------------------------------------------
print("[9] Guvenli loadstring ornekleri...")

local safe_load = AntiTamper.create_safe_loadstring({
    max_size = 10000,
    blocked_patterns = {
        "os%.execute",
        "io%.open",
        "debug%.",
        "loadfile",
        "dofile",
    }
})

-- Güvenli kod
local func1, err1 = safe_load("return 42")
if func1 then
    print("  Guvenli kod yuklendi, sonuc: " .. tostring(func1()))
end

-- Tehlikeli kod
local func2, err2 = safe_load('os.execute("whoami")')
print("  Tehlikeli kod yuklendi mi: " .. tostring(func2 ~= nil) .. " (false olmali)")
print("  Engelleme sebebi: " .. tostring(err2))
print()

-------------------------------------------------------------------------------
-- 10) Zamanlama Kontrolü
-------------------------------------------------------------------------------
print("[10] Zamanlama kontrolleri...")

AntiTamper.start_timing("islem1")

-- Biraz iş yap
local toplam = 0
for i = 1, 10000 do toplam = toplam + i end

AntiTamper.timing_checkpoint("islem1", "hesaplama_bitti")

local t_ok, t_elapsed = AntiTamper.end_timing("islem1", 0, 5.0)
print("  Zamanlama testi: " .. tostring(t_ok) .. " (sure: " .. tostring(t_elapsed) .. "s)")

-- Zamanlama saldırısı kontrolü
local timing_ok, timing_elapsed = AntiTamper.check_timing_attack()
print("  Zamanlama saldirisi kontrolu: " .. tostring(timing_ok))
print()

-------------------------------------------------------------------------------
-- 11) Execution Token
-------------------------------------------------------------------------------
print("[11] Yurutme tokenleri...")

local token_val = AntiTamper.create_execution_token("islem_token", 60)
print("  Token olusturuldu: " .. tostring(token_val))

local v_ok, v_msg = AntiTamper.validate_execution_token("islem_token", token_val)
print("  Token dogrulama: " .. tostring(v_ok))

-- Yanlış token
local v2_ok, v2_msg = AntiTamper.validate_execution_token("islem_token", 12345)
print("  Yanlis token dogrulama: " .. tostring(v2_ok) .. " - " .. tostring(v2_msg))

-- Tek kullanımlık token
local ot_val, ot_validate = AntiTamper.create_one_time_token("tek_kullanimlik")
print("  Tek kullanimlik token: " .. tostring(ot_val))

local ot1 = ot_validate(ot_val)
print("  Ilk kullanim: " .. tostring(ot1) .. " (true olmali)")

local ot2 = ot_validate(ot_val)
print("  Ikinci kullanim: " .. tostring(ot2) .. " (false olmali)")
print()

-------------------------------------------------------------------------------
-- 12) Dijital Filigran
-------------------------------------------------------------------------------
print("[12] Dijital filigran...")

local wm = AntiTamper.create_watermark("MyApp_License_v2")
print("  Filigran olusturuldu: " .. tostring(wm.hash))

local wm_ok = AntiTamper.verify_watermark(wm)
print("  Filigran dogrulama: " .. tostring(wm_ok))

-- Filigranlı fonksiyon
local function onemli_fonk(x)
    return x * x
end

local wm_fonk = AntiTamper.embed_watermark(onemli_fonk, "kritik_fonksiyon")
print("  Filigranli fonksiyon sonucu: " .. tostring(wm_fonk(7)))
print()

-------------------------------------------------------------------------------
-- 13) Stack Canary
-------------------------------------------------------------------------------
print("[13] Stack canary kontrolleri...")

local canary1 = AntiTamper.create_stack_canary("test_canary_1")
local canary2 = AntiTamper.create_stack_canary("test_canary_2")
print("  Canary 1: " .. tostring(canary1))
print("  Canary 2: " .. tostring(canary2))

local c_ok = AntiTamper.verify_canary("test_canary_1", canary1)
print("  Canary 1 dogrulama: " .. tostring(c_ok))

local all_c_ok = AntiTamper.verify_stack_canaries()
print("  Tum canary'ler dogru mu: " .. tostring(all_c_ok))
print()

-------------------------------------------------------------------------------
-- 14) Heartbeat (Kalp Atışı)
-------------------------------------------------------------------------------
print("[14] Heartbeat sistemi...")

-- Manuel pulse
local hb_ok, hb_results = AntiTamper.pulse()
print("  Heartbeat pulse: " .. tostring(hb_ok))
if hb_results then
    for check_name, check_ok in pairs(hb_results) do
        print("    " .. check_name .. " = " .. tostring(check_ok))
    end
end

-- Otomatik heartbeat (coroutine)
local auto_hb = AntiTamper.create_auto_heartbeat({
    interval = 0.5,
    checks   = { "runtime_integrity", "hooks" }
})

-- Birkaç tick çalıştır
for i = 1, 3 do
    local tick_ok = auto_hb()
    print("  Auto heartbeat tick " .. i .. ": " .. tostring(tick_ok))
end

AntiTamper.stop_heartbeat()
print("  Heartbeat durduruldu.")
print()

-------------------------------------------------------------------------------
-- 15) Modül İzolasyonu
-------------------------------------------------------------------------------
print("[15] Modul izolasyonu...")

local safe_require = AntiTamper.create_safe_require(
    { "string", "table", "math" },  -- İzin verilenler
    { "os", "io", "debug" }          -- Yasaklananlar
)

-- İzin verilen modül
local s_ok2 = pcall(function()
    local s = safe_require("string")
end)
print("  string modulu yuklenebilir mi: " .. tostring(s_ok2))

-- Yasaklı modül
local d_ok2 = pcall(function()
    safe_require("os")
end)
print("  os modulu yuklenebilir mi: " .. tostring(d_ok2) .. " (false olmali)")
print()

-------------------------------------------------------------------------------
-- 16) Guard (Otomatik Koruma)
-------------------------------------------------------------------------------
print("[16] Guard (otomatik koruma)...")

local guard = AntiTamper.create_guard({
    interval = 0.5,
    checks   = { "quick" },
    on_tamper = function(failures)
        print("  [GUARD] Tamper tespit edildi!")
        for _, f in ipairs(failures) do
            print("    Check: " .. tostring(f.check))
        end
    end
})

-- Birkaç tick çalıştır
for i = 1, 3 do
    local g_ok = guard.tick()
    print("  Guard tick " .. i .. ": " .. tostring(g_ok))
end

local stats = guard.get_stats()
print("  Guard kontrol sayisi: " .. tostring(stats.check_count))
guard.stop()
print("  Guard durduruldu.")
print()

-------------------------------------------------------------------------------
-- 17) Tam Tarama
-------------------------------------------------------------------------------
print("[17] Tam butunluk taramasi...")

local scan = AntiTamper.full_scan()
print("  Gecen: " .. scan.passed .. "/" .. scan.total)
print("  Butunluk skoru: %" .. scan.integrity_score)

for check_name, check_result in pairs(scan.checks) do
    local mark = check_result.passed and "[OK]" or "[FAIL]"
    print("  " .. mark .. " " .. check_name)
    if check_result.error then
        print("       Hata: " .. tostring(check_result.error))
    end
end
print()

-------------------------------------------------------------------------------
-- 18) Olay Günlüğü
-------------------------------------------------------------------------------
print("[18] Son 10 olay gunlugu:")
local recent_log = AntiTamper.get_log(10)
for _, entry in ipairs(recent_log) do
    print(string.format("  [%s] %s: %s",
        tostring(entry.time),
        tostring(entry.event),
        tostring(entry.details)
    ))
end
print()

-------------------------------------------------------------------------------
-- 19) Desteklenen Olaylar
-------------------------------------------------------------------------------
print("[19] Desteklenen olay tipleri:")
local events = AntiTamper.list_event_types()
for i, event in ipairs(events) do
    print("  " .. i .. ". " .. event)
end
print()

-------------------------------------------------------------------------------
-- 20) Final Durum
-------------------------------------------------------------------------------
print("[20] Final durum raporu:")
local final_status = AntiTamper.get_status()
for k, v in pairs(final_status) do
    print("  " .. tostring(k) .. " = " .. tostring(v))
end

print()
print("=" .. string.rep("=", 68))
print("  TAMAMLANDI - Tum ornekler basariyla calistirildi")
print("=" .. string.rep("=", 68))
