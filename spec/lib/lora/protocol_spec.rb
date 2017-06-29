require_relative '../../../lib/lora/protocol'

#=============================================================
# PHYPayload
#=============================================================
describe 'PHYPayload' do

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
                nwkid:   0b1000001,
                nwkaddr: 0b0_01110000_01111000_01111100
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
          ["40" + "7c787082" + "00" + "0201" + "" + "01" + "0102030405060708"].pack('H*')
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
        )
      }

      it 'without encryption' do
        expect(phypayload.encode).to eql(
          ["00" + "0807060504030201" + "1817161514131211" + "2221"].pack('H*')
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
            appnonce: AppNonce.new(value: "\x01\x02\x03"),
            netid: NetId.new(
              addr:    0b0_01111000_01111100,
              nwkid:   0b1000001
            ),
            devaddr: DevAddr.new(
              nwkid:   0b1000001,
              nwkaddr: 0b0_01110000_01111000_01111100
            ),
            dlsettings: DLSettings.new(
              rx1droffset: 0,
              rx2datarate: 1
            ),
            rxdelay: 2,
            cflist: CFList.new(
              #ch3: ChannelFrequency.new(value: 923_200_000),
              #ch4: ChannelFrequency.new(value: 923_400_000),
              #ch5: ChannelFrequency.new(value: 923_600_000),
              #ch6: ChannelFrequency.new(value: 923_800_000),
              #ch7: ChannelFrequency.new(value: 924_000_000),
              ch3: 923_200_000,
              ch4: 923_400_000,
              ch5: 923_600_000,
              ch6: 923_800_000,
              ch7: 924_000_000,
            )
          ),
          mic: '',
        )
      }

      it 'without encryption' do
        expect(phypayload.encode).to eql(
          ["20" + "030201" + "413e3c" + "7c787082" + "01" + "02" +
           "8cde80" + "8ce650" + "8cee20" + "8cf5f0" + "8cfdc0" + "00"].pack('H*')
        )
      end

      it 'encryption' do
        encode         = phypayload.encode
        encode_encrypt = phypayload.encode(appkey: appkey)

	p encode.to_hexstr
	p encode_encrypt.to_hexstr

        expect(encode_encrypt[0]).to eql encode[0]
        expect(encode_encrypt[1..27]).not_to eql encode[1..27]        # encrypted
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
      #         nwkid:   0b1000001,
      #         nwkaddr: 0b0_01110000_01111000_01111100
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
        ['407c787082000201010102030405060708'].pack('H*')
      }
      let(:phypayload_encoded_encrypt) {
        ['407c787082000201015ebf8ac02d342a116c4f434c'].pack('H*')
      }

      it 'without encryption' do
        phypayload = PHYPayload.from_bytes(phypayload_encoded_without_encrypt)

        expect(phypayload.mhdr.class).to eql MHDR
        expect(phypayload.mhdr.mtype).to eql MHDR::UnconfirmedDataUp
        expect(phypayload.mhdr.major).to eql 0

        expect(phypayload.macpayload.class).to eql MACPayload

        expect(phypayload.macpayload.fhdr.class).to eql FHDR

        expect(phypayload.macpayload.fhdr.devaddr.class).to   eql DevAddr
        expect(phypayload.macpayload.fhdr.devaddr.nwkid).to   eql 0b1000001
        expect(phypayload.macpayload.fhdr.devaddr.nwkaddr).to eql 0b0_01110000_01111000_01111100

        expect(phypayload.macpayload.fhdr.fctrl.class).to     eql FCtrl
        expect(phypayload.macpayload.fhdr.fctrl.adr).to       be false
        expect(phypayload.macpayload.fhdr.fctrl.adrackreq).to be false
        expect(phypayload.macpayload.fhdr.fctrl.fpending).to  be false
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
        expect(phypayload.macpayload.fhdr.devaddr.nwkid).to   eql 0b1000001
        expect(phypayload.macpayload.fhdr.devaddr.nwkaddr).to eql 0b0_01110000_01111000_01111100

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
      #  )
      let(:phypayload_encoded_without_encrypt) {
        ['00080706050403020118171615141312112221'].pack('H*')
      }

      it 'without encryption' do
        phypayload = PHYPayload.from_bytes(phypayload_encoded_without_encrypt)

        expect(phypayload.mhdr.class).to eql MHDR
        expect(phypayload.mhdr.mtype).to eql MHDR::JoinRequest
        expect(phypayload.mhdr.major).to eql 0

        expect(phypayload.macpayload.class).to    eql JoinRequestPayload
        expect(phypayload.macpayload.appeui ).to   eql ['0102030405060708'].pack('H*')
        expect(phypayload.macpayload.deveui ).to   eql ['1112131415161718'].pack('H*')
        expect(phypayload.macpayload.devnonce ).to eql ['2122'].pack('H*')
      end
    end


    describe 'join accept' do
      #  PHYPayload.new(
      #    mhdr: MHDR.new(
      #      mtype: MHDR::JoinAccept
      #    ),
      #    macpayload: JoinAcceptPayload.new(
      #      appnonce: "\x01\x02\x03",
      #      netid: NetId.new(
      #        addr:    0b0_01111000_01111100,
      #        nwkid:   0b1000001
      #      ),
      #      devaddr: DevAddr.new(
      #        nwkid:   0b1000001,
      #        nwkaddr: 0b0_01110000_01111000_01111100
      #      ),
      #      dlsettings: DLSettings.new(
      #        rx1droffset: 0,
      #        rx2datarate: 1
      #      ),
      #      rxdelay: 2,
      #      cflist: CFList.new(
      #        ch3: 923_200_000,
      #        ch4: 923_400_000,
      #        ch5: 923_600_000,
      #        ch6: 923_800_000,
      #        ch7: 924_000_000,
      #      )
      #    ),
      #    mic: '',
      #  )
      let(:phypayload_encoded_without_encrypt) {
        ['20030201413e3c7c78708201028cde808ce6508cee208cf5f08cfdc000'].pack('H*')
      }
      let(:phypayload_encoded_encrypt) {
        ['2082f517ae0b972a1869a7e6cbf61e3d3484c073d44f5765c191783bd3fe4c3103'].pack('H*')
       }


      it 'without encryption' do
        phypayload = PHYPayload.from_bytes(phypayload_encoded_without_encrypt)

        expect( phypayload.mhdr.class ).to eql MHDR
        expect( phypayload.mhdr.mtype ).to eql MHDR::JoinAccept
        expect( phypayload.mhdr.major ).to eql 0

        expect( phypayload.macpayload.appnonce ).to eql "\x01\x02\x03"

        expect( phypayload.macpayload.netid.nwkid ).to eql 0b1000001
        expect( phypayload.macpayload.netid.addr ).to  eql 0b0_01111000_01111100

        expect( phypayload.macpayload.devaddr.nwkid ).to   eql 0b1000001
        expect( phypayload.macpayload.devaddr.nwkaddr ).to eql 0b0_01110000_01111000_01111100

        expect( phypayload.macpayload.dlsettings.rx1droffset ).to eql 0
        expect( phypayload.macpayload.dlsettings.rx2datarate ).to eql 1

        expect( phypayload.macpayload.rxdelay ).to eql 2

        expect( phypayload.macpayload.cflist ).not_to eql nil
        expect( phypayload.macpayload.cflist.ch3 ).to eql 923_200_000
        expect( phypayload.macpayload.cflist.ch7 ).to eql 924_000_000
      end


      it 'with encryption' do
        phypayload = PHYPayload.from_bytes(phypayload_encoded_encrypt, appkey: appkey)

        expect( phypayload.mhdr.class ).to eql MHDR
        expect( phypayload.mhdr.mtype ).to eql MHDR::JoinAccept
        expect( phypayload.mhdr.major ).to eql 0

        expect( phypayload.macpayload.appnonce ).to eql "\x01\x02\x03"

        expect( phypayload.macpayload.netid.nwkid ).to eql 0b1000001
        expect( phypayload.macpayload.netid.addr ).to  eql 0b0_01111000_01111100

        expect( phypayload.macpayload.devaddr.nwkid ).to   eql 0b1000001
        expect( phypayload.macpayload.devaddr.nwkaddr ).to eql 0b0_01110000_01111000_01111100

        expect( phypayload.macpayload.dlsettings.rx1droffset ).to eql 0
        expect( phypayload.macpayload.dlsettings.rx2datarate ).to eql 1

        expect( phypayload.macpayload.rxdelay).to eql 2

        expect( phypayload.macpayload.cflist ).not_to eql nil
        expect( phypayload.macpayload.cflist.ch3 ).to eql 923_200_000
        expect( phypayload.macpayload.cflist.ch7 ).to eql 924_000_000
      end
    end
  end
end


#=============================================================
# ChannelFrequency
#=============================================================
describe 'ChannelFrequency' do
  describe 'encode/decode' do
    let(:cflist) {
      ChannelFrequency.new(
        value: 923_200_000
      )
    }

    it 'raw access' do
      expect( cflist.value ).to eql 923_200_000
    end

    it 'encode' do
      expect( cflist.encode ).to eql ["8cde80"].pack('H*')  # as 923_200_0
    end

    it 'decode' do
      chf = ChannelFrequency.from_bytes("\x8c\xde\x80")
      expect( cflist.value ).to eql 923_200_000
    end
  end
end


#=============================================================
# CFList
#=============================================================
describe 'CFList' do
  describe 'encode/decode' do
    let(:cflist) {
      CFList.new(
        ch3: ChannelFrequency.new(value: 923_200_000),
        ch4: ChannelFrequency.new(value: 923_400_000),
        ch5: ChannelFrequency.new(value: 923_600_000),
        ch6: ChannelFrequency.new(value: 923_800_000),
        ch7: ChannelFrequency.new(value: 924_000_000),
      )
    }

    it 'encode' do
      expect( cflist.encode ).to eql ["8cde80" + "8ce650" + "8cee20" + "8cf5f0" + "8cfdc0" + "00"].pack('H*')
    end

    it 'decode' do
      cflist = CFList.from_bytes(["8cde80" + "8ce650" + "8cee20" + "8cf5f0" + "8cfdc0" + "00"].pack('H*'))
      expect( cflist.ch3 ).to eql 923_200_000
      expect( cflist.ch7 ).to eql 924_000_000
    end
  end
  
end


