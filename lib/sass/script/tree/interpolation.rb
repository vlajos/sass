module Sass::Script::Tree
  # A SassScript object representing `#{}` interpolation outside a string.
  #
  # @see StringInterpolation
  class Interpolation < Node
    # @return [Node] The SassScript before the interpolation
    attr_reader :before

    # @return [Node] The SassScript within the interpolation
    attr_reader :mid

    # @return [Node] The SassScript after the interpolation
    attr_reader :after

    # @return [Boolean] Whether there was whitespace between `before` and `#{`
    attr_reader :whitespace_before

    # @return [Boolean] Whether there was whitespace between `}` and `after`
    attr_reader :whitespace_after

    # @return [Boolean] Whether the original format of the interpolation was
    #   plain text, not an interpolation. This is used when converting back to
    #   SassScript.
    attr_reader :originally_text

    # @return [Boolean] Whether a color value passed to the interpolation should
    #   generate a warning.
    attr_reader :warn_for_color

    # Interpolation in a property is of the form `before #{mid} after`.
    #
    # @param before [Node] See {Interpolation#before}
    # @param mid [Node] See {Interpolation#mid}
    # @param after [Node] See {Interpolation#after}
    # @param wb [Boolean] See {Interpolation#whitespace_before}
    # @param wa [Boolean] See {Interpolation#whitespace_after}
    # @param originally_text [Boolean] See {Interpolation#originally_text}
    # @param warn_for_color [Boolean] See {Interpolation#warn_for_color}
    # @comment
    #   rubocop:disable ParameterLists
    def initialize(before, mid, after, wb, wa, originally_text = false, warn_for_color = false)
      # rubocop:enable ParameterLists
      @before = before
      @mid = mid
      @after = after
      @whitespace_before = wb
      @whitespace_after = wa
      @originally_text = originally_text
      @warn_for_color = warn_for_color
    end

    # @return [String] A human-readable s-expression representation of the interpolation
    def inspect
      "(interpolation #{@before.inspect} #{@mid.inspect} #{@after.inspect})"
    end

    # @see Node#to_sass
    def to_sass(opts = {})
      res = ""
      res << @before.to_sass(opts) if @before
      res << ' ' if @before && @whitespace_before
      res << '#{' unless @originally_text
      res << @mid.to_sass(opts)
      res << '}' unless @originally_text
      res << ' ' if @after && @whitespace_after
      res << @after.to_sass(opts) if @after
      res
    end

    # Returns the three components of the interpolation, `before`, `mid`, and `after`.
    #
    # @return [Array<Node>]
    # @see #initialize
    # @see Node#children
    def children
      [@before, @mid, @after].compact
    end

    # @see Node#deep_copy
    def deep_copy
      node = dup
      node.instance_variable_set('@before', @before.deep_copy) if @before
      node.instance_variable_set('@mid', @mid.deep_copy)
      node.instance_variable_set('@after', @after.deep_copy) if @after
      node
    end

    protected

    def _to_sexp(visitor)
      block = s(:block)
      if @before
        before_var = visitor.environment.unique_ident(:before)
        block << s(:lasgn, before_var, @before.to_sexp(visitor))
      end
      mid_var = visitor.environment.unique_ident(:mid)
      block << s(:lasgn, mid_var, @mid.to_sexp(visitor))
      block << s(:if, s(:call, s(:lvar, mid_var), :is_a?, sass(:Script, :Value, :String)),
        s(:lasgn, mid_var, s(:call, s(:lvar, mid_var), :value)))
      if @after
        after_var = visitor.environment.unique_ident(:after)
        block << s(:lasgn, after_var, @after.to_sexp(visitor))
      end

      if @warn_for_color
        location = "line #{line}, column #{source_range.start_pos.offset}"
        location << " of #{filename}" if filename
        alternative = Operation.new(Sass::Script::Value::String.new("", :string), @mid, :plus)
        block << s(:call, sass(:Script, :Helpers), :maybe_warn_for_color,
                   s(:lvar, mid_var),
                   s(:str, location),
                   s(:str, alternative.to_sass))
      end

      interp = s(:dstr, "")
      interp << s(:evstr, s(:lvar, before_var)) if @before
      interp << s(:str, ' ') if @before && @whitespace_before
      interp << s(:evstr, s(:lvar, mid_var))
      interp << s(:str, ' ') if @after && @whitespace_after
      interp << s(:evstr, s(:lvar, after_var)) if @after
      block << s(:call, sass(:Script, :Value, :String), :new, interp)
    end

    # Evaluates the interpolation.
    #
    # @param environment [Sass::Environment] The environment in which to evaluate the SassScript
    # @return [Sass::Script::Value::String]
    #   The SassScript string that is the value of the interpolation
    def _perform(environment)
      res = ""
      res << @before.perform(environment).to_s if @before
      res << " " if @before && @whitespace_before

      val = @mid.perform(environment)
      if @warn_for_color && val.is_a?(Sass::Script::Value::Color) && val.name
        alternative = Operation.new(Sass::Script::Value::String.new("", :string), @mid, :plus)
        Sass::Util.sass_warn <<MESSAGE
WARNING on line #{line}, column #{source_range.start_pos.offset}#{" of #{filename}" if filename}:
You probably don't mean to use the color value `#{val}' in interpolation here.
It may end up represented as #{val.inspect}, which will likely produce invalid CSS.
Always quote color names when using them as strings (for example, "#{val}").
If you really want to use the color value here, use `#{alternative.to_sass}'.
MESSAGE
      end

      res << val.to_s(:quote => :none)
      res << " " if @after && @whitespace_after
      res << @after.perform(environment).to_s if @after
      opts(Sass::Script::Value::String.new(res))
    end
  end
end
