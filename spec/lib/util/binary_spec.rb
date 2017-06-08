require_relative '../../../lib/util/binary'

describe 'initializer ' do
  before(:context) do
    class Hoge
      include Binary
      attr_accessor :a, :b, :c

      define_option_params_initializer with: ->{ @inner_attr = 'setted' }
    end
  end

  it 'can take parameters(Hash)' do
    expect{ Hoge.new(a: 1, b: 2, c: 3) }.not_to raise_error
  end

  it 'execute lamdba' do
    expect( Hoge.new.instance_variable_get(:@inner_attr) ).to eql 'setted'
  end
end




describe 'bit_structure' do
  before(:context) do
    class Hoge
      include Binary

      bit_structure [
        :little_endian,
        [34..9,  :a,  :numeric],   # 26bit
        [ 8..2,  :b,  :flag],      #  7bit
        [ 1..0,  :c,  :enum, {     #  2bit
                        elem1: 1,
                        elem2: 2}],
      ]
      define_option_params_initializer with: ->{ @inner_attr = 'setted' }
    end
  end


  describe 'methods defined' do
    it 'class methods defined' do
      expect( Hoge ).to respond_to :bit_structure
      expect( Hoge ).to respond_to :define_option_params_initializer
      expect( Hoge ).to respond_to :from_bytes
    end

    it 'instance has encode/decode' do
      expect( Hoge.new ).to respond_to :encode
      expect( Hoge.new ).to respond_to :decode

      expect( Hoge.new ).to respond_to :a
      expect( Hoge.new ).to respond_to :a=
      expect( Hoge.new ).to respond_to :decode_a

      expect( Hoge.new ).to respond_to :b
      expect( Hoge.new ).to respond_to :b=
      expect( Hoge.new ).to respond_to :b?
      expect( Hoge.new ).to respond_to :decode_b

      expect( Hoge.new ).to respond_to :c
      expect( Hoge.new ).to respond_to :c=
      expect( Hoge.new ).to respond_to :decode_c
    end
  end


  describe 'const defined' do
    it 'include ElemX' do
      expect( Hoge.constants ).to include :Elem1
      expect( Hoge.constants ).to include :Elem2
    end
  end


  describe 'method access' do
    let(:instance) {
      Hoge.new a: 1, b: true, c: Hoge::Elem1
    }

    it 'attribute reader' do
      expect( instance.a ).to eql 1
      expect( instance.b ).to be true
      expect( instance.c ).to eql Hoge::Elem1
    end

    it 'attribute writer' do
      expect{ instance.a = 2       }.not_to raise_error
      expect{ instance.a = 2**26-1 }.not_to raise_error
      expect{ instance.a = 2**26   }.to raise_error ArgumentError   # overflow

      expect{ instance.b = true    }.not_to raise_error
      expect{ instance.b = false   }.not_to raise_error
      expect{ instance.b = 0       }.not_to raise_error
      expect{ instance.b = 1       }.not_to raise_error
      expect{ instance.b = 2       }.to raise_error ArgumentError  # flag can takes only true/false/1/0

      expect{ instance.c = Hoge::Elem2 }.not_to raise_error
      expect{ instance.c = 3           }.to raise_error ArgumentError  # undefined value
    end

    it 'flag value 1/0 is changed as true/false' do
      instance.b = 1
      expect( instance.b ).to be true

      instance.b = 0
      expect( instance.b ).to be false
    end
  end


  describe 'encode' do
    let(:instance) {
      Hoge.new(
        a: 0b10_00000000_00000000_00000001,
        b: true,
        c: Hoge::Elem1
      )
    }

    it 'encode' do
      expect( instance.encode ).to eql "\x05\x02\x00\x00\x04"
    end
  end


  describe 'decode' do
    let(:bytes) {
      "\x05\x02\x00\x00\x04"
    }

    it 'from_bytes' do
      Hoge.from_bytes(bytes).tap do |instance|
        expect( instance.a ).to eql 0b10_00000000_00000000_00000001
        expect( instance.b ).to be true
        expect( instance.c ).to eql Hoge::Elem1 
      end
    end
  end
end

