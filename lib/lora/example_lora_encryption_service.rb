require_relative 'protocol'
require_relative 'lora_encryption'
require_relative 'lora_encryption_service'


# NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
# AppSKey = aes128_encrypt(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad16)

appkey = ['01010101010101010101010101010101'].pack('H*')
@raw=" w\xBF#\x03\x02\x01{\xF0;\x06\x00\x00",

               # pre    appnonce      netid           devnonce
nwkskey_base = "\x01" + "w\xBF#" + "\x03\x02\x01" + "\x21\x22"
appskey_base = "\x02" + "w\xBF#" + "\x03\x02\x01" + "\x21\x22"

#pp LoRaEncryption.encrypt_aes(nwkskey_base, appkey).to_hexstr
#pp LoRaEncryption.encrypt_aes(appskey_base, appkey).to_hexstr


phy_req =
        PHYPayload.new(
          mhdr: MHDR.new(
            mtype: MHDR::JoinRequest
          ),
          macpayload: JoinRequestPayload.new(
            appeui:   AppEUI.new(value: "\x01\x02\x03\x04\x05\x06\x07\x08"),
            deveui:   DevEUI.new(value: "\x11\x12\x13\x14\x15\x16\x17\x18"),
            devnonce: DevNonce.new(value: "\x22\x21")
          ),
          mic: '',
          direction: :up
        )

phy_ack = 
        PHYPayload.new(
          mhdr: MHDR.new(
            mtype: MHDR::JoinAccept
          ),
          macpayload: JoinAcceptPayload.new(
            appnonce: AppNonce.new(value: "#\xBFw"),
            netid: NetId.new(
              nwkid:   0b0000000,
              addr:    0b1_00000010_00000011
            ),
            devaddr: DevAddr.new(
              nwkid:   0b1001000,
              nwkaddr: 0b0_10010001_10010010_10010011
            ),
            dlsettings: DLSettings.new(
              rx1droffset: 0,
              rx2datarate: 1
            ),
            rxdelay: 2,
            cflist: CFList.new(
              ch3: 923_200_000,
              ch4: 923_400_000,
              ch5: 923_600_000,
              ch6: 923_800_000,
              ch7: 924_000_000,
            )
          ),
          mic: '',
        )

p phy_ack.macpayload.appnonce.encode
p phy_ack.macpayload.netid.encode
p phy_req.macpayload.devnonce.encode

gen = KeyGenerator.new(phy_req, phy_ack, appkey)
nwkskey, appskey = gen.get_keys
p nwkskey.to_hexstr
p appskey.to_hexstr

