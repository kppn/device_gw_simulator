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
           "80de8c" + "50e68c" + "20ee8c" + "f0f58c" + "c0fd8c" + "00"].pack('H*')
        )
      end

      it 'encryption' do
        encode         = phypayload.encode
        # as 20030201413e3c7c787082010280de8c50e68c20ee8cf0f58cc0fd8c00 
        
        encode_encrypt = phypayload.encode(appkey: appkey)
        # as 20da662c2dba161240832c1747a4e50c64d10d22d4d6c555edf86227aeaa03e0be

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
        ['20030201413e3c7c787082010280de8c50e68c20ee8cf0f58cc0fd8c00'].pack('H*')
      }
      let(:phypayload_encoded_encrypt) {
        ['20da662c2dba161240832c1747a4e50c64d10d22d4d6c555edf86227aeaa03e0be'].pack('H*')
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
      expect( cflist.encode ).to eql ["80de8c"].pack('H*')  # as 923_200_0
    end

    it 'decode' do
      chf = ChannelFrequency.from_bytes("\x80\xde\x8c")
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
      expect( cflist.encode ).to eql ["80de8c" + "50e68c" + "20ee8c" + "f0f58c" + "c0fd8c" + "00"].pack('H*')
    end

    it 'decode' do
      cflist = CFList.from_bytes(["80de8c" + "50e68c" + "20ee8c" + "f0f58c" + "c0fd8c" + "00"].pack('H*'))
      expect( cflist.ch3 ).to eql 923_200_000
      expect( cflist.ch7 ).to eql 924_000_000
    end
  end
  
end



#=============================================================
# LinkCheckReq/LinkCheckAns
#=============================================================
describe 'LinkCheckReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::LinkCheck,
        payload: LinkCheckReq.new
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["02"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["02"].pack('H*'), :up)

      expect( command.cid ).to eql 2
      expect( command.payload.class ).to eql LinkCheckReq
    end
  end
end

describe 'LinkCheckAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::LinkCheck,
        payload: LinkCheckAns.new(
          margin: 255,
          gwcnt: 255
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["02" + "ff" + "ff"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["02" + "ff" + "ff"].pack('H*'), :down)

      expect( command.cid ).to eql 2
      expect( command.payload.class ).to eql LinkCheckAns
      expect( command.payload.margin ).to eql 255
      expect( command.payload.gwcnt ).to eql 255
    end
  end
end


#=============================================================
# LinkADRReq/LinkADRAns
#=============================================================
describe 'LinkADRReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::LinkADR,
        payload: LinkADRReq.new(
          datarate: LinkADRReq::Sf7250khz,
          txpower: LinkADRReq::MaxeirpMinus14db,
          chmask: 0xabcd,
          chmaskctl: 7,
          nbtrans: 3
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["03" + "67" + "cdab" + "73"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["03" + "67" + "cdab" + "73"].pack('H*'), :down)

      expect( command.cid ).to eql 3
      expect( command.payload.class ).to eql LinkADRReq
      expect( command.payload.datarate).to eql 6
      expect( command.payload.txpower).to eql 7
      expect( command.payload.chmask).to eql 0xabcd
      expect( command.payload.chmaskctl).to eql 7
      expect( command.payload.nbtrans).to eql 3

    end
  end
end

describe 'LinkADRAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::LinkADR,
        payload: LinkADRAns.new(
          powerack: true,
          datarateack: true,
          channelmaskack: true
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["03" + "07"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["03" + "07"].pack('H*'), :up)

      expect( command.cid ).to eql 3
      expect( command.payload.class ).to eql LinkADRAns
      expect( command.payload.powerack).to be_truthy
      expect( command.payload.datarateack).to be_truthy
      expect( command.payload.channelmaskack).to be_truthy
    end
  end
end


#=============================================================
# DutyCycleReq/DutyCycleAns
#=============================================================
describe 'DutyCycleReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DutyCycle,
        payload: DutyCycleReq.new(
          maxdcycle: 15
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["04" + "0f"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["04" + "0f"].pack('H*'), :down)

      expect( command.cid ).to eql 4
      expect( command.payload.class ).to eql DutyCycleReq
      expect( command.payload.maxdcycle).to eql 15
    end
  end
end

describe 'DutyCycleAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DutyCycle,
        payload: DutyCycleAns.new
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["04"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["04"].pack('H*'), :up)

      expect( command.cid ).to eql 4
      expect( command.payload.class ).to eql DutyCycleAns
    end
  end
end


#=============================================================
# RXParamSetupReq/RXParamSetupAns
#=============================================================
describe 'RXParamSetupReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::RXParamSetup,
        payload: RXParamSetupReq.new(
          dlsettings: DLSettings.new(
            rx1droffset: 7,
            rx2datarate: 15
          ),
          frequency: 923_200_000
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["05" + "7f" + "80de8c"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["05" + "7f" + "80de8c"].pack('H*'), :down)

      expect( command.cid ).to eql 5
      expect( command.payload.class ).to eql RXParamSetupReq
      expect( command.payload.dlsettings.rx1droffset).to eql 7
      expect( command.payload.dlsettings.rx2datarate).to eql 15
    end
  end
end

describe 'RXParamSetupAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::RXParamSetup,
        payload: RXParamSetupAns.new(
          status: RXParamSetupAnsStatus.new(
            rx1droffsetack: true,
            rx2droffsetack: true,
            channelack:     true
          )
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["05" + "07"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["05" + "07"].pack('H*'), :up)

      expect( command.cid ).to eql 5
      expect( command.payload.class ).to eql RXParamSetupAns
      expect( command.payload.status.rx1droffsetack ).to be_truthy
      expect( command.payload.status.rx2droffsetack).to be_truthy
      expect( command.payload.status.channelack).to be_truthy
    end
  end
end


#=============================================================
# DevStatusReq/DevStatusAns
#=============================================================
describe 'DevStatusReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DevStatus,
        payload: DevStatusReq.new
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["06"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["06"].pack('H*'), :down)

      expect( command.cid ).to eql 6
      expect( command.payload.class ).to eql DevStatusReq
    end
  end
end

describe 'DevStatusAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DevStatus,
        payload: DevStatusAns.new(
          battery: 255,
          margin: -32
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["06" + "ff" + "20"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["06" + "ff" + "20"].pack('H*'), :up)

      expect( command.cid ).to eql 6
      expect( command.payload.class ).to eql DevStatusAns
      expect( command.payload.battery ).to eql 255
      expect( command.payload.margin ).to eql -32
    end
  end
end


#=============================================================
# NewChannelReq/NewChannelAns
#=============================================================
describe 'NewChannelReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::NewChannel,
        payload: NewChannelReq.new(
          chindex: 255,
          frequency: 923_200_000,
          drrange: DrRange.new(
            maxdr: 15,
            mindr: 15
          )
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["07" + "ff" + "80de8c" + "ff"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["07" + "ff" + "80de8c" + "ff"].pack('H*'), :down)

      expect( command.cid ).to eql 7
      expect( command.payload.class ).to eql NewChannelReq
      expect( command.payload.chindex).to eql 255
      expect( command.payload.frequency).to eql 923_200_000
      expect( command.payload.drrange.maxdr).to eql 15
      expect( command.payload.drrange.mindr).to eql 15

    end
  end
end

describe 'NewChannelAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::NewChannel,
        payload: NewChannelAns.new(
          status: NewChannelAnsStatus.new(
            dataraterangeok: true,
            channelfrequencyok: true,
          )
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["07" + "03"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["07" + "03"].pack('H*'), :up)

      expect( command.cid ).to eql 7
      expect( command.payload.class ).to eql NewChannelAns
      expect( command.payload.status.dataraterangeok).to be_truthy
      expect( command.payload.status.channelfrequencyok).to be_truthy
    end
  end
end


#=============================================================
# RXTimingSetupReq/RXTimingSetupAns
#=============================================================
describe 'RXTimingSetupReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::RXTimingSetup,
        payload: RXTimingSetupReq.new(
          del: 15
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["08" + "0f"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["08" + "0f"].pack('H*'), :down)

      expect( command.cid ).to eql 8
      expect( command.payload.class ).to eql RXTimingSetupReq
      expect( command.payload.del).to eql 15

    end
  end
end

describe 'RXTimingSetupAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::RXTimingSetup,
        payload: RXTimingSetupAns.new
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["08"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["08"].pack('H*'), :up)

      expect( command.cid ).to eql 8
      expect( command.payload.class ).to eql RXTimingSetupAns
    end
  end
end


#=============================================================
# TxParamSetupReq/TxParamSetupAns
#=============================================================
describe 'TxParamSetupReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::TxParamSetup,
        payload: TxParamSetupReq.new(
          eirpdwelltime: EIRPDwellTime.new(
            downlinkdwelltime: EIRPDwellTime::Dwelltime400ms,
            uplinkdwelltime:   EIRPDwellTime::Dwelltime400ms,
            maxeirp: EIRPDwellTime::Maxeirp36dbm
          )
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["09" + "3f"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["09" + "3f"].pack('H*'), :down)

      expect( command.cid ).to eql 9
      expect( command.payload.class ).to eql TxParamSetupReq
      expect( command.payload.eirpdwelltime.downlinkdwelltime ).to be_truthy
      expect( command.payload.eirpdwelltime.uplinkdwelltime).to be_truthy
      expect( command.payload.eirpdwelltime.maxeirp).to eql 15

    end
  end
end

describe 'TxParamSetupAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::TxParamSetup,
        payload: TxParamSetupAns.new
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["09"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["09"].pack('H*'), :up)

      expect( command.cid ).to eql 9
      expect( command.payload.class ).to eql TxParamSetupAns
    end
  end
end


#=============================================================
# DlChannelReq/DlChannelAns
#=============================================================
describe 'DlChannelReq' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DlChannel,
        payload: DlChannelReq.new(
          chindex: 15,
          freq: 923_200_000
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["0a" + "0f" + "80de8c"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["0a" + "0f" + "80de8c"].pack('H*'), :down)

      expect( command.cid ).to eql 10
      expect( command.payload.class ).to eql DlChannelReq
      expect( command.payload.freq ).to eql 923_200_000
    end
  end
end

describe 'DlChannelAns' do
  describe 'encode/decode' do
    let(:command) {
      MACCommand.new(
        cid: MACCommand::DlChannel,
        payload: DlChannelAns.new(
          status: DlChannelAnsStatus.new(
            uplinkfrequencyexists: true,
            channelfrequencyok: true
          )
        )
      )
    }

    it 'encode' do
      expect( command.encode ).to eql ["0a" + "03"].pack('H*')
    end

    it 'decode' do
      command = MACCommand.from_bytes(["0a" + "03"].pack('H*'), :up)

      expect( command.cid ).to eql 10
      expect( command.payload.class ).to eql DlChannelAns
      expect( command.payload.status.uplinkfrequencyexists).to be_truthy
      expect( command.payload.status.channelfrequencyok).to be_truthy
    end
  end
end


