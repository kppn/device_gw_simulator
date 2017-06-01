require_relative '../lora/protocol'
require 'pp'


phypayload = PHYPayload.new(
  mhdr: MHDR.new(
    mtype: MHDR::UnconfirmedDataUp
  ),
  macpayload: MACPayload.new(
    fhdr: FHDR.new(
      devaddr: DevAddr.new(
        # 0x26041652
        nwkid:   0b0010_011,
        nwkaddr: 0b0_0000_0100_0001_0110_0101_0010
      ),
      fctrl: FCtrl.new(
        adr:        false,
        adrackreq:  false,
        ack:        false,
        fpending:   false,
        foptslen:   1
      ),
      fcnt: 0,
      fopts: ["02"].pack('H*')
    ),
    fport: 0,
    frmpayload: FRMPayload.new(
      #"hello"
      #["02"].pack('H*')
      ""
    )
  ),
  mic: '',
  direction: :up
)

appskey = ["7BF7C495B7C12A92CB856B35FCD18598"].pack('H*')
nwkskey = ["AF0196F6C67B5B65D20B925BCF010290"].pack('H*')

pp phypayload
enc = phypayload.encode(appskey, nwkskey)
pp enc.to_hexstr

pp PHYPayload.from_bytes(enc, appskey, :up)

