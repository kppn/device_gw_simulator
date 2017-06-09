#!/home/ta_kondoh/.rbenv/shims/ruby

require 'pp'

require_relative 'core_ext'

module Binary
  module BinarySingletons
    # define bit oriented access methods
    # following methods are defined
    #   type flag
    #       * attr                   #=> true / false
    #       * attr=(val)             # 1 / true / 0 / false) 
    #       * attr?                  #=> true / false
    #       * decode_attr(byte_str)  # e.g.) "\x01\x02"
    #   type numeric
    #       * attr                   #=> value
    #       * attr=(val)             # val
    #       * decode_attr(byte_str)  # e.g.) "\x01\x02"
    #   type enum
    #       * attr                   #=> value
    #       * attr=(val)             # val
    #       * enum_name?             #=> true / false
    #       * decode_attr(byte_str)  # e.g.) "\x01\x02"
    #
    # Type enum defines constants for the class, like
    # EnumName. if no enumerated value is specified,
    # setter raises ArgumentError.
    #       
    def bit_structure(defs)
      const_set('Endian', fetch_endian(defs))
      const_set('Defs', form_definitions(defs))

      const_set('ByteWidth', byte_width(self::Defs))

      self::Defs.each do |name, params|
        next if name.to_s == 'undefined'

        define_attr_decode_method(name, params)

        case params[:type]
        when :flag
          define_flag_methods name, params
        when :numeric
          define_numeric_methods name, params
        when :enum
          define_enum_methods name, params
        else
          raise ArgumentError.new("bit structure #{name}. type must be :flag or :numeric pr :enum")
        end
      end

      nil
    end


    # define class wrapped accessor
    #
    # usage
    #
    #   class Wrapper
    #     attr_accessor :value
    #   end
    #
    #   class Hoge
    #     bit_structure [
    #       [7..0, hoge, :numeric]
    #     ]
    #     wrapped_accessor(
    #       hoge: [Wrapper, value]
    #     )
    #   end
    #
    # same as 
    #   class Hoge
    #     def hoge(v)
    #       @hoge.value
    #     end
    #     def hoge=(v)
    #       if v.kind_of? Integer || v.kind_of? String
    #         @hoge ||= Wrapper.new
    #         @hoge.value = v
    #       elsif v.kind_of? Wrapper
    #         @hoge = v
    #       end
    #     end
    #   end
    #
    def wrapped_accessor(attrs)
      self.class_eval do
        attrs.each do |attr, (wrap_klass, wrap_klass_attr)|
          # define getter
          define_method("#{attr}") do 
            instance_variable_get("@#{attr.to_s}")&.send(wrap_klass_attr)
          end

          # define setter
          define_method("#{attr}=") do |val|
            case val
            when wrap_klass
              instance_variable_set("@#{attr.to_s}", val)
            else
              attr_name = "@#{attr.to_s}"
              unless instance_variable_get(attr_name)
                instance_variable_set(attr_name, wrap_klass.new)
              end
              instance_variable_get(attr_name).send("#{wrap_klass_attr}=", val)
            end
          end
        end
      end
    end

    # define params initializer
    # same as following
    #   class Hoge
    #     attr_accessor :a, :b
    #
    #     def initialize(params)
    #       a = params[:a]
    #       b = params[:b]
    #     end
    #   end
    def define_option_params_initializer(options = {})
      define_method(:initialize) do |init_params = {}|
        init_params.each do |name, val|
          self.send("#{name.to_s}=", val)
        end

        instance_exec &options[:with] if options[:with]
      end
    end



    
    private 

    def fetch_endian(defs)
      defs[0] == :little_endian ? defs.shift : nil
    end

    # form_definitions
    #  bit_structure [
    #    [7,    :hoge,  :flag],
    #    [2..0, :foo,   :enum, {
    #                      e_foo0: :e_foo_value0
    #                      e_foo1: :e_foo_value1
    #                    }
    #    ],
    #  ]
    #  =>
    #  {
    #    hoge: {
    #      {pos: 7..7, type: :flag,    opt: nil}
    #    },
    #    foo: {
    #      {pos: 0..2, type: :enum,    opt: {e_foo0: :e_foo_value0, e_foo1: :e_foo_value1}}
    #    }
    #  }
    def form_definitions(defs)
      hash = {}
      defs.each do |d|
        r = case d[0]
            when Integer
              Range.new(d[0], d[0])
            when Range
              Range.new(* [d[0].first, d[0].last].sort)
            end
        hash[d[1]] = { pos: r, type: d[2], opt: d[3] }
      end

      hash
    end

    def byte_width(defs)
      msb = defs.map{|_, params| params[:pos].last}.max
      (msb+7) / 8
    end

    def define_attr_decode_method(name, params)
      shift_width = params[:pos].first
      mask        = (1 << params[:pos].size) - 1

      width = self::ByteWidth
      unpack_to_int = Proc.new {|byte_str|
        byte_str = self::Endian == :little_endian ? byte_str.reverse : byte_str
        bytes = byte_str.each_byte.to_a[0..width]
        bytes.inject(0){|s, x| s * 256 + x}
      }

      define_method("decode_#{name}") do |byte_str|
        raw_num = unpack_to_int.call(byte_str)
        num = (raw_num >> shift_width) & mask
        self.send("#{name}=", num)
      end
    end


    # setter:  obj.a_flag = true
    #          obj.a_flag = 1
    # getter:  obj.a_flag     #=> 1
    # boolean: obj.a_flag?    #=> true
    def define_flag_methods(name, params)
      if params[:pos].size != 1
        ArgumentError.new("type :flag must be 1 bit, but actual #{params[:pos]}")
      end
      define_basic_getter name
      define_flag_setter  name
      define_flag_boolean name
    end


    # setter:  obj.a_value = 3
    # getter:  obj.a_value     #=> 3
    def define_numeric_methods(name, params)
      define_basic_getter name
      define_basic_setter name, params
    end


    # setter:  obj.a_value          #=> true
    # getter:  obj.a_value = true
    # boolean: obj.a_value?         #=> true
    def define_enum_methods(name, params)
      define_basic_getter name
      define_enum_setter name, params
      define_enum_boolean name, params
      define_enum_constants name, params
    end


    def define_basic_getter(name)
      define_method(name) do
        instance_variable_get("@#{name}")
      end
    end

    def define_basic_setter(name, params)
      define_method("#{name.to_s}=") do |val|
        unless valid_range_value?(val, params[:pos])
          raise ArgumentError.new("#{name} = #{val} for bit #{params[:pos]} overflow")
        end
        instance_variable_set("@#{name}", val)
      end
    end

    def define_flag_setter(name)
      define_method("#{name.to_s}=") do |val|
        val = form_flag_value(val)
        instance_variable_set("@#{name}", val)
      end
    end

    def define_flag_boolean(name)
      define_method("#{name.to_s}?") do
        instance_variable_get("@#{name}")
      end
    end

    def define_enum_boolean(name, params)
      params[:opt].each do |enum_name, enum_value|
        define_method("#{enum_name}?") do
          self.send(name) == enum_value
        end
      end
    end

    def define_enum_setter(name, params)
      define_method("#{name.to_s}=") do |val|
        unless params[:opt].values.include?(val)
          raise ArgumentError.new("undefined value #{val} for #{name}")
        end
        instance_variable_set("@#{name}", val)
      end
    end

    def define_enum_constants(name, params)
      params[:opt].each do |enum_name, enum_value|
        camel_name = enum_name.to_s.split('_').map{|w| w[0].upcase + w[1..-1]}.join
        const_set(camel_name, enum_value)
      end
    end
  end


  def self.included(klass)
    klass.class_eval do
      # define singleton methods
      extend BinarySingletons

      #==================================================
      # class methods
      #==================================================
      def self.from_bytes(byte_str)
        self.new.decode(byte_str)
      end

      #==================================================
      # instance methods
      #==================================================
      def decode(byte_str)
        self.class::Defs.keys.each do |name|
          next if name.to_s == 'undefined'

          self.send("decode_#{name}", byte_str)
        end
        self
      end

      def encode
        value = 0
        self.class::Defs.each do |name, params|
          next if name.to_s == 'undefined'

          val = self.send(name)
          shift_width = params[:pos].first
          mask = (1 << params[:pos].size) - 1
          bit_oriented_value = (val.to_i & mask) << shift_width
          value |= bit_oriented_value
        end

        pack = make_pack(self.class::ByteWidth)
        packed = pack.call(value)

        self.class::Endian == :little_endian ?  packed.reverse : packed
      end


      private

      def form_flag_value(val)
        unless [0, 1, true, false].include?(val)
          raise ArgumentError.new('value for flag must be 0/1 or true/false')
        end
        if [0, 1].include?(val)
          val = val.to_boolean
        end
        val
      end

      def valid_range_value?(val, pos)
        val >= 0 && val.bit_length <= pos.size
      end

      def make_pack(width)
        Proc.new{|value|
          octs = width.times.map{
            oct = value % 256
            value /= 256
            oct
          }.reverse
          octs.pack('C*').force_encoding('ASCII-8BIT')
        }
      end
    end
  end

end

