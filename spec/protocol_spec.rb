require_relative '../lib/lora/protocol'

describe 'encode' do
  let(:appkey)  { ["01" * 16].pack('H*') }
  let(:appskey) { ["01" * 16].pack('H*') }
  let(:nwkskey) { ["01" * 16].pack('H*') }
      

  describe 'data payload' do

    let(:phypayload) {
      PHYPayload.new(
        mhdr: MHDR.new(
          mtype: MHDR::UnconfirmedDataUp
        ),
        macpayload: MACPayload.new(
          fhdr: FHDR.new(
            devaddr: DevAddr.new(
              nwkid:   0b1000000,
              nwkaddr: 0b0_10000001_10000010_10000011
            ),
            fctrl: FCtrl.new(
              adr: false,
              adrackreq: false,
              ack: false
            ),
            fcnt: 258,
            fopts: nil
          ),
          fport: 1,
          frmpayload: FRMPayload.new("\x01\x02\x03\x04\x05\x06\x07\x08")
        ),
        mic: '',
      )
    }


    it 'without encryption' do
      expect(phypayload.encode).to eql(
        ["40" + "83828180" + "00" + "0201" + "" + "01" + "0102030405060708"].pack('H*')
      )
    end

    it 'encryption' do
      encode         = phypayload.encode
      encode_encrypt = phypayload.encode(appskey: appskey, nwkskey: nwkskey)

      expect(encode_encrypt[0..7]).to eql encode[0..7]
      expect(encode_encrypt[8..15]).not_to eql encode[8..15]        # encrypted
      expect(encode_encrypt.bytesize).to eql encode.bytesize + 4    # MIC appended
    end
  end


  describe 'join request' do
    let(:phypayload) {
      PHYPayload.new(
        mhdr: MHDR.new(
          mtype: MHDR::JoinRequest
        ),
        macpayload: JoinRequestPayload.new(
          appeui: "\x01\x02\x03\x04\x05\x06\x07\x08",
          deveui: "\x11\x12\x13\x14\x15\x16\x17\x18",
          devnonce: "\x21\x22"
        ),
        mic: '',
        direction: :up
      )
    }

    it 'without encryption' do
      expect(phypayload.encode).to eql(
        ["00" + "0102030405060708" + "1112131415161718" + "2122"].pack('H*')
      )
    end
  end


  describe 'join accept' do
    let(:phypayload) {
      PHYPayload.new(
        mhdr: MHDR.new(
          mtype: MHDR::JoinAccept
        ),
        macpayload: JoinAcceptPayload.new(
          appnonce: AppNonce.new(value: 0x010203),
          netid:    NetId.new(
                      nwkid:   0b1000000,
                      addr:    0b0_10000001_10000010
                    ),
          devaddr: DevAddr.new(
                     nwkid:   0b1001000,
                     nwkaddr: 0b0_10010001_10010010_10010011
                   ),
          dlsettings: "\x01",
          rxdelay: "\x02",
        ),
        mic: '',
        direction: :up
      )
    }

    it 'without encryption' do
      expect(phypayload.encode).to eql(
        ["20" + "030201" + "828180" + "93929190" + "01" + "02"].pack('H*')
      )
    end

    it 'encryption' do
      encode         = phypayload.encode
      encode_encrypt = phypayload.encode(appkey: appkey)

      expect(encode_encrypt[0]).to eql encode[0]
      expect(encode_encrypt[1..12]).not_to eql encode[1..12]        # encrypted
      expect(encode_encrypt.bytesize).to eql encode.bytesize + 4    # MIC appended
    end

  end
end



describe 'decode' do
  let(:appkey)  { ["01" * 16].pack('H*') }
  let(:appskey) { ["01" * 16].pack('H*') }
  let(:nwkskey) { ["01" * 16].pack('H*') }

  describe 'data payload' do
    # data as 
    # PHYPayload.new(
    #   mhdr: MHDR.new(
    #     mtype: MHDR::UnconfirmedDataUp
    #   ),
    #   macpayload: MACPayload.new(
    #     fhdr: FHDR.new(
    #       devaddr: DevAddr.new(
    #         nwkid:   0b1000000,
    #         nwkaddr: 0b0_10000001_10000010_10000011
    #       ),
    #       fctrl: FCtrl.new(
    #         adr: false,
    #         adrackreq: false,
    #         ack: false
    #       ),
    #       fcnt: 258,
    #       fopts: nil
    #     ),
    #     fport: 1,
    #     frmpayload: FRMPayload.new("\x01\x02\x03\x04\x05\x06\x07\x08")
    #   ),
    #   mic: '',
    #   direction: :up
    # )

    let(:phypayload_encoded_without_encrypt) {
      ['4083828180000201010102030405060708'].pack('H*')
    }
    let(:phypayload_encoded_encrypt) {
      ['40838281800002010108d2b505feea80b27c08d373'].pack('H*')
    }

    it 'without encryption' do
      phypayload = PHYPayload.from_bytes(phypayload_encoded_without_encrypt)

      expect(phypayload.mhdr.class).to eql MHDR
      expect(phypayload.mhdr.mtype).to eql MHDR::UnconfirmedDataUp
      expect(phypayload.mhdr.major).to eql 0

      expect(phypayload.macpayload.class).to eql MACPayload

      expect(phypayload.macpayload.fhdr.class).to eql FHDR

      expect(phypayload.macpayload.fhdr.devaddr.class).to   eql DevAddr
      expect(phypayload.macpayload.fhdr.devaddr.nwkid).to   eql 0b1000000
      expect(phypayload.macpayload.fhdr.devaddr.nwkaddr).to eql 0b0_10000001_10000010_10000011

      expect(phypayload.macpayload.fhdr.fctrl.class).to     eql FCtrl
      expect(phypayload.macpayload.fhdr.fctrl.adr).to       eql false
      expect(phypayload.macpayload.fhdr.fctrl.adrackreq).to eql false
      expect(phypayload.macpayload.fhdr.fctrl.fpending).to  eql false
      expect(phypayload.macpayload.fhdr.fctrl.foptslen).to  eql 0

      expect(phypayload.macpayload.fhdr.fcnt).to   eql 258
      expect(phypayload.macpayload.fhdr.fopts).to  eql nil

      expect(phypayload.macpayload.fport).to eql 1

      expect(phypayload.macpayload.frmpayload.value).to eql "\x01\x02\x03\x04\x05\x06\x07\x08"
    end

    it 'with encryption' do
      phypayload = PHYPayload.from_bytes(phypayload_encoded_encrypt, appskey: appskey, nwkskey: nwkskey)

      expect(phypayload.mhdr.class).to eql MHDR
      expect(phypayload.mhdr.mtype).to eql MHDR::UnconfirmedDataUp
      expect(phypayload.mhdr.major).to eql 0

      expect(phypayload.macpayload.class).to eql MACPayload

      expect(phypayload.macpayload.fhdr.class).to eql FHDR

      expect(phypayload.macpayload.fhdr.devaddr.class).to   eql DevAddr
      expect(phypayload.macpayload.fhdr.devaddr.nwkid).to   eql 0b1000000
      expect(phypayload.macpayload.fhdr.devaddr.nwkaddr).to eql 0b0_10000001_10000010_10000011

      expect(phypayload.macpayload.fhdr.fctrl.class).to     eql FCtrl
      expect(phypayload.macpayload.fhdr.fctrl.adr).to       eql false
      expect(phypayload.macpayload.fhdr.fctrl.adrackreq).to eql false
      expect(phypayload.macpayload.fhdr.fctrl.fpending).to  eql false
      expect(phypayload.macpayload.fhdr.fctrl.foptslen).to  eql 0

      expect(phypayload.macpayload.fhdr.fcnt).to   eql 258
      expect(phypayload.macpayload.fhdr.fopts).to  eql nil

      expect(phypayload.macpayload.fport).to eql 1

      expect(phypayload.macpayload.frmpayload).to eql "\x01\x02\x03\x04\x05\x06\x07\x08"
    end
  end

  describe 'join request' do
    # data as
    #  PHYPayload.new(
    #    mhdr: MHDR.new(
    #      mtype: MHDR::JoinRequest
    #    ),
    #    macpayload: JoinRequestPayload.new(
    #      appeui: "\x01\x02\x03\x04\x05\x06\x07\x08",
    #      deveui: "\x11\x12\x13\x14\x15\x16\x17\x18",
    #      devnonce: "\x21\x22"
    #    ),
    #    mic: '',
    #    direction: :up
    #  )
    let(:phypayload_encoded_without_encrypt) {
      ['00010203040506070811121314151617182122'].pack('H*')
    }

    it 'without encryption' do
      phypayload = PHYPayload.from_bytes(phypayload_encoded_without_encrypt)

      expect(phypayload.mhdr.class).to eql MHDR
      expect(phypayload.mhdr.mtype).to eql MHDR::JoinRequest
      expect(phypayload.mhdr.major).to eql 0

      expect(phypayload.macpayload.class).to    eql JoinRequestPayload
      expect(phypayload.macpayload.appeui).to   eql ['0102030405060708'].pack('H*')
      expect(phypayload.macpayload.deveui).to   eql ['1112131415161718'].pack('H*')
      expect(phypayload.macpayload.devnonce).to eql ['2122'].pack('H*')
    end
  end
end


