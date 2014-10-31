module Sass
  module Script
    module Helpers
      class << self
        def arg_hash(map)
          Sass::Util::NormalizedMap.new(Sass::Util.map_keys(map.to_h) do |key|
            next key.value if key.is_a?(Sass::Script::Value::String)
            raise Sass::SyntaxError.new("Variable keyword argument map must have string keys.\n" +
              "#{key.inspect} is not a string in #{map.inspect}.")
          end)
        end

        def maybe_warn_for_color(val, location, alternative)
          return unless val.is_a?(Sass::Script::Value::Color) && val.name
          Sass::Util.sass_warn <<MESSAGE
WARNING on #{location}:
You probably don't mean to use the color value `#{val}' in interpolation here.
It may end up represented as #{val.inspect}, which will likely produce invalid CSS.
Always quote color names when using them as strings (for example, "#{val}").
If you really want to use the color value here, use `#{alternative}'.
MESSAGE
        end
      end
    end
  end
end
