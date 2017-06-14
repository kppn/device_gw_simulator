require_relative '../../../lib/util/binary'

describe 'initializer ' do
  before(:context) do
    class Hoge
      include Binary
      attr_accessor :a, :b, :c

      define_option_params_initializer with: ->{ @inner_attr = 'setted' }
    end
  end
  after(:context) do
    Object.send(:remove_const, :Hoge)
  end

  it 'can take parameters(Hash)' do
    expect{ Hoge.new(a: 1, b: 2, c: 3) }.not_to raise_error
  end

  it 'execute lamdba' do
    expect( Hoge.new.instance_variable_get(:@inner_attr) ).to eql 'setted'
  end
end


describe 'wrapper' do
  before(:context) do
    class Hoge
      attr_accessor :hoge_attr
    end

    class Fuga
      attr_accessor :fuga_attr
    end

    class Foo
      include Binary

      wrapped_accessor({
        hoge: [Hoge, :hoge_attr],
        fuga: [Fuga, :fuga_attr]
      })
    end
  end
  after(:context) do
    Object.send(:remove_const, :Hoge)
    Object.send(:remove_const, :Fuga)
    Object.send(:remove_const, :Foo)
  end

  describe 'still wrapped value' do
    let(:foo) {
      foo = Foo.new
      foo.hoge = Hoge.new.tap{|hoge| hoge.hoge_attr = 1}
      foo
    }

    it 'setted as native' do
      expect( foo.instance_variable_get("@hoge").class ).to eql Hoge
      expect( foo.instance_variable_get("@hoge").hoge_attr ).to eql 1 
    end
  end

  describe 'dynamic wrapped value' do
    let(:foo) {
      foo = Foo.new
      foo.hoge = 1
      foo.fuga = 'aaa'
      foo
    }

    it 'accessed as raw but wrapped as Class' do
      expect( foo.hoge ).to eql 1
      expect( foo.instance_variable_get("@hoge").class ).to eql Hoge
      expect( foo.instance_variable_get("@hoge").hoge_attr).to eql 1 
      expect( foo.instance_variable_get("@hoge").hoge_attr.class).to eql Integer

      expect( foo.fuga ).to eql 'aaa'
      expect( foo.instance_variable_get("@fuga").class ).to eql Fuga
      expect( foo.instance_variable_get("@fuga").fuga_attr).to eql 'aaa'
      expect( foo.instance_variable_get("@fuga").fuga_attr.class).to eql String
    end
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
  after(:context) do
    Object.send(:remove_const, :Hoge)
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


describe 'wrapper binary octets' do
  before(:context) do
    class Hoge
      include Binary

      bit_structure [
        :little_endian,
        [63..0, :hoge_attr, :octets]
      ]
    end

    class Foo
      include Binary

      wrapped_accessor({
        hoge: [Hoge, :hoge_attr],
      })
    end
  end
  after(:context) do
    Object.send(:remove_const, :Hoge)
    Object.send(:remove_const, :Foo)
  end

  describe 'octets' do
    let(:hoge) {
      hoge = Hoge.new
      hoge.hoge_attr = ["0001020304050607"].pack('H*')
      hoge
    }

    it 'encode' do
      expect( hoge.encode ).to eql ["0706050403020100"].pack('H*')
    end

  end

  describe 'still wrapped value' do
    let(:foo) {
      foo = Foo.new
      foo.hoge = Hoge.new.tap{|hoge| hoge.hoge_attr = ["0001020304050607"].pack('H*')}
      foo
    }

    it 'setted as native' do
      expect( foo.instance_variable_get("@hoge").class ).to eql Hoge
      expect( foo.instance_variable_get("@hoge").hoge_attr ).to eql ["0001020304050607"].pack('H*')
    end
  end
end


describe 'mix binary octets and other' do
  before(:context) do
    class Hoge
      include Binary

      bit_structure [
        [39..32, :hoge_attr5, :numeric],
        [31..24, :hoge_attr4, :octets],
        [23..8,  :hoge_attr3, :octets],
        [7..4,   :hoge_attr2, :numeric],
        [3..0,   :hoge_attr1, :numeric],
      ]
    end
  end
  after(:context) do
    Object.send(:remove_const, :Hoge)
  end

  describe 'octets' do
    let(:hoge) {
      hoge = Hoge.new
      hoge.hoge_attr1 = 0x5
      hoge.hoge_attr2 = 0xa
      hoge.hoge_attr3 = ["0102"].pack('H*')
      hoge.hoge_attr4 = ["11"].pack('H*')
      hoge.hoge_attr5 = 0xf
      hoge
    }

    it 'access' do
      expect( hoge.hoge_attr1 ).to eql 0x5
      expect( hoge.hoge_attr2 ).to eql 0xa
      expect( hoge.hoge_attr3 ).to eql ["0102"].pack('H*')
      expect( hoge.hoge_attr4 ).to eql ["11"].pack('H*')
      expect( hoge.hoge_attr5 ).to eql 0xf
    end

    it 'encode' do
      expect( hoge.encode ).to eql ["0f110102a5"].pack('H*')
    end

    it 'decode' do
      hoge = Hoge.from_bytes(["0f110102a5"].pack('H*'))
      expect( hoge.hoge_attr1 ).to eql 0x5
      expect( hoge.hoge_attr2 ).to eql 0xa
      expect( hoge.hoge_attr3 ).to eql ["0102"].pack('H*')
      expect( hoge.hoge_attr4 ).to eql ["11"].pack('H*')
      expect( hoge.hoge_attr5 ).to eql 0xf
    end
  end
end



