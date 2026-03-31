-- ===================================================================
-- VİZE PROJESİ: 2SIEM-lite (Çok Kaynaklı Log Birleştirme ve Alarm Sistemi)
-- ===================================================================

CREATE DATABASE SIEM_Lite_DB;
GO
USE SIEM_Lite_DB;
GO

-- ==========================================
-- 1. DDL SCRİPTLERİ (Tablo Oluşturma)
-- ==========================================
CREATE TABLE Kaynak (
    KaynakID INT IDENTITY(1,1) PRIMARY KEY,
    CihazAdi VARCHAR(100) NOT NULL,
    IP_Adresi VARCHAR(15) UNIQUE NOT NULL,
    CihazTipi VARCHAR(50) NOT NULL
);

CREATE TABLE Kural (
    KuralID INT IDENTITY(1,1) PRIMARY KEY,
    KuralAdi VARCHAR(100) NOT NULL,
    HedefSeviye VARCHAR(10) NOT NULL CHECK (HedefSeviye IN ('INFO', 'WARN', 'ERROR', 'FATAL')),
    ZamanPenceresi_Dk INT NOT NULL CHECK (ZamanPenceresi_Dk > 0),
    EsikDeger INT NOT NULL CHECK (EsikDeger > 0)
);

CREATE TABLE Event_Log (
    LogID BIGINT IDENTITY(1,1) PRIMARY KEY,
    KaynakID INT NOT NULL FOREIGN KEY REFERENCES Kaynak(KaynakID),
    Seviye VARCHAR(10) NOT NULL CHECK (Seviye IN ('INFO', 'WARN', 'ERROR', 'FATAL')),
    Mesaj VARCHAR(500) NOT NULL,
    OlusturulmaTarihi DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Alarm (
    AlarmID BIGINT IDENTITY(1,1) PRIMARY KEY,
    KuralID INT NOT NULL FOREIGN KEY REFERENCES Kural(KuralID),
    KaynakID INT NOT NULL FOREIGN KEY REFERENCES Kaynak(KaynakID),
    TetiklenmeTarihi DATETIME DEFAULT CURRENT_TIMESTAMP,
    Durum VARCHAR(20) DEFAULT 'ACIK' CHECK (Durum IN ('ACIK', 'INCELENIYOR', 'KAPALI')),
    Aciklama VARCHAR(255)
);
GO

-- ==========================================
-- 2. PROGRAMLANABİLİRLİK (View, Function, SP, Trigger)
-- ==========================================

-- VIEW
CREATE VIEW vw_AktifAlarmlar AS
SELECT a.AlarmID, k.CihazAdi, k.IP_Adresi, kr.KuralAdi, a.TetiklenmeTarihi, a.Durum
FROM Alarm a
JOIN Kaynak k ON a.KaynakID = k.KaynakID
JOIN Kural kr ON a.KuralID = kr.KuralID
WHERE a.Durum != 'KAPALI';
GO

-- FUNCTION
CREATE FUNCTION fn_LogSayisiGetir (@KaynakID INT, @Seviye VARCHAR(10))
RETURNS INT AS
BEGIN
    DECLARE @Toplam INT;
    SELECT @Toplam = COUNT(*) FROM Event_Log WHERE KaynakID = @KaynakID AND Seviye = @Seviye;
    RETURN @Toplam;
END;
GO

-- STORED PROCEDURE
CREATE PROCEDURE sp_YeniLogEkle
    @IP_Adresi VARCHAR(15), @Seviye VARCHAR(10), @Mesaj VARCHAR(500) AS
BEGIN
    DECLARE @BulunanKaynakID INT;
    SELECT @BulunanKaynakID = KaynakID FROM Kaynak WHERE IP_Adresi = @IP_Adresi;
    IF @BulunanKaynakID IS NOT NULL
        INSERT INTO Event_Log (KaynakID, Seviye, Mesaj) VALUES (@BulunanKaynakID, @Seviye, @Mesaj);
    ELSE
        PRINT 'HATA: Bu IP adresine sahip bir cihaz sistemde kayitli degil!';
END;
GO

-- TRIGGER
CREATE TRIGGER trg_EsikKontrol_AlarmUret
ON Event_Log AFTER INSERT AS
BEGIN
    DECLARE @EklenenKaynakID INT, @EklenenSeviye VARCHAR(10);
    DECLARE @SonZaman DATETIME, @Esik INT, @Pencere INT, @KuralID INT, @HataSayisi INT;

    SELECT @EklenenKaynakID = KaynakID, @EklenenSeviye = Seviye FROM inserted;

    IF @EklenenSeviye IN ('ERROR', 'FATAL')
    BEGIN
        SELECT TOP 1 @KuralID = KuralID, @Esik = EsikDeger, @Pencere = ZamanPenceresi_Dk 
        FROM Kural WHERE HedefSeviye = @EklenenSeviye;

        SET @SonZaman = DATEADD(minute, -@Pencere, CURRENT_TIMESTAMP);

        SELECT @HataSayisi = COUNT(*) FROM Event_Log 
        WHERE KaynakID = @EklenenKaynakID AND Seviye = @EklenenSeviye AND OlusturulmaTarihi >= @SonZaman;

        IF @HataSayisi >= @Esik
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM Alarm WHERE KuralID = @KuralID AND KaynakID = @EklenenKaynakID AND Durum = 'ACIK')
            BEGIN
                INSERT INTO Alarm (KuralID, KaynakID, Aciklama)
                VALUES (@KuralID, @EklenenKaynakID, 'SIEM OTOMATIK ALARM: Kural esigi asildi!');
            END
        END
    END
END;
GO

-- ==========================================
-- 3. DML SCRİPTLERİ (Örnek Veri Ekleme)
-- ==========================================
INSERT INTO Kaynak (CihazAdi, IP_Adresi, CihazTipi) VALUES 
('Ana_Firewall', '192.168.1.1', 'Firewall'),
('Web_Sunucu_1', '192.168.1.10', 'WebServer'),
('DB_Sunucu', '10.0.0.5', 'Database');

INSERT INTO Kural (KuralAdi, HedefSeviye, ZamanPenceresi_Dk, EsikDeger) VALUES 
('Yuksek Hata Orani', 'ERROR', 5, 3),
('Kritik Cokme', 'FATAL', 1, 1); 

INSERT INTO Event_Log (KaynakID, Seviye, Mesaj) VALUES 
(1, 'INFO', 'Admin basariyla giris yapti.'),
(2, 'WARN', 'Disk alani %80 dolu.'),
(2, 'ERROR', 'Sayfa bulunamadi (404).'),
(3, 'INFO', 'Yedekleme tamamlandi.');
GO

-- ==========================================
-- 4. TEMEL VE İLERİ SORGULAR (Hocanın İsterleri)
-- ==========================================
-- Temel Sorgu: Hatalı logları cihaz adıyla getirme
SELECT k.CihazAdi, k.IP_Adresi, l.Seviye, l.Mesaj, l.OlusturulmaTarihi 
FROM Event_Log l
JOIN Kaynak k ON l.KaynakID = k.KaynakID
WHERE l.Seviye IN ('ERROR', 'FATAL');

-- İleri Sorgu: Birden fazla hata veren cihazları çoktan aza gruplama
SELECT k.CihazAdi, COUNT(l.LogID) AS ToplamHataSayisi
FROM Event_Log l
JOIN Kaynak k ON l.KaynakID = k.KaynakID
WHERE l.Seviye = 'ERROR'
GROUP BY k.CihazAdi
HAVING COUNT(l.LogID) > 1
ORDER BY ToplamHataSayisi DESC;