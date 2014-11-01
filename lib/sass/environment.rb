require 'set'

module Sass
  # The abstract base class for lexical environments for SassScript.
  class BaseEnvironment
    class << self
      # Note: when updating this,
      # update sass/yard/inherited_hash.rb as well.
      def inherited_hash_accessor(name)
        inherited_hash_reader(name)
        inherited_hash_writer(name)
      end

      def inherited_hash_reader(name)
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{name}(name)
            _#{name}(name.tr('_', '-'))
          end

          def _#{name}(name)
            (@#{name}s && @#{name}s[name]) || @parent && @parent._#{name}(name)
          end
          protected :_#{name}

          def is_#{name}_global?(name)
            return !@parent if @#{name}s && @#{name}s.has_key?(name)
            @parent && @parent.is_#{name}_global?(name)
          end
        RUBY
      end

      def inherited_hash_writer(name)
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def set_#{name}(name, value)
            name = name.tr('_', '-')
            @#{name}s[name] = value unless try_set_#{name}(name, value)
          end

          def try_set_#{name}(name, value)
            @#{name}s ||= {}
            if @#{name}s.include?(name)
              @#{name}s[name] = value
              true
            elsif @parent && !@parent.global?
              @parent.try_set_#{name}(name, value)
            else
              false
            end
          end
          protected :try_set_#{name}

          def set_local_#{name}(name, value)
            @#{name}s ||= {}
            @#{name}s[name.tr('_', '-')] = value
          end

          def set_global_#{name}(name, value)
            global_env.set_#{name}(name, value)
          end
        RUBY
      end
    end

    # The options passed to the Sass Engine.
    attr_reader :options

    attr_writer :caller
    attr_writer :content
    attr_writer :selector

    # variable
    # Script::Value
    inherited_hash_reader :var

    # mixin
    # Sass::Callable
    inherited_hash_reader :mixin

    # function
    # Sass::Callable
    inherited_hash_reader :function

    inherited_hash_reader :fn
    inherited_hash_writer :fn

    inherited_hash_reader :mx
    inherited_hash_writer :mx

    inherited_hash_writer :var

    # @param options [{Symbol => Object}] The options hash. See
    #   {file:SASS_REFERENCE.md#sass_options the Sass options documentation}.
    # @param parent [Environment] See \{#parent}
    def initialize(parent = nil, options = nil, mapper = nil, fn_signatures = nil, mx_signatures = nil)
      @fn_signatures = fn_signatures
      @mx_signatures = mx_signatures
      @parent = parent
      @options = options || (parent && parent.options) || {}
      @stack = Sass::Stack.new if @parent.nil?
      @mapper = mapper
      @ident_count = 0
      @idents = {}
    end

    def unique_ident(name = nil)
      return global_env.unique_ident(name) unless global?
      @ident_count += 1
      "_s_#{(name || 'i').to_s.gsub(/[^a-zA-Z0-9_]/, '_')}_#{@ident_count}"
    end

    def fn_variable(name)
      ident, function = fn(name)
      return unless ident
      ident = "@#{ident}" if is_fn_global?(name)
      return ident, function
    end

    def declare_fn(name, function)
      ident = set_local_fn(name, [unique_ident("fn_#{name}"), function]).first
      global? ? "@#{ident}" : ident
    end

    def mx_variable(name)
      ident, mixin = mx(name)
      return unless ident
      ident = "@#{ident}" if is_mx_global?(name)
      return ident, mixin
    end

    def declare_mx(name, mixin)
      ident = set_local_mx(name, [unique_ident("mx_#{name}"), mixin]).first
      global? ? "@#{ident}" : ident
    end

    def var_variable(name)
      return unless (ident = var(name))
      return is_var_global?(name) ? "@#{ident}" : ident
    end

    def declare_var(name)
      ident = set_local_var(name, unique_ident("var_#{name}"))
      global? ? "@#{ident}" : ident
    end

    def declare_global_var(name)
      global_env.declare_var(name)
    end

    # Returns whether this is the global environment.
    #
    # @return [Boolean]
    def global?
      @parent.nil?
    end

    # The environment of the caller of this environment's mixin or function.
    # @return {Environment?}
    def caller
      @caller || (@parent && @parent.caller)
    end

    def mapper
      @mapper || (@parent && @parent.mapper)
    end

    def fn_signatures
      @fn_signatures || (@parent && @parent.fn_signatures)
    end

    def mx_signatures
      @mx_signatures || (@parent && @parent.mx_signatures)
    end

    # The content passed to this environment. This is naturally only set
    # for mixin body environments with content passed in.
    #
    # @return {[Array<Sass::Tree::Node>, Environment]?} The content nodes and
    #   the lexical environment of the content block.
    def content
      @content || (@parent && @parent.content)
    end

    # The selector for the current CSS rule, or nil if there is no
    # current CSS rule.
    #
    # @return [Selector::CommaSequence?] The current selector, with any
    #   nesting fully resolved.
    def selector
      @selector || (@caller && @caller.selector) || (@parent && @parent.selector)
    end

    # The top-level Environment object.
    #
    # @return [Environment]
    def global_env
      @global_env ||= global? ? self : @parent.global_env
    end

    # The import/mixin stack.
    #
    # @return [Sass::Stack]
    def stack
      mapper.stack_for Kernel.caller
    end

    def run_function(context, name, splat)
      callable = fn_signatures[name]
      return run_callable(context, callable, splat) if callable
      # TODO: throw an error if splat has keywords.
      Sass::Script::Value::String.new("#{name}(#{splat.to_a.join(', ')})")
    end

    def run_mixin(context, name, splat)
      callable = mx_signatures[name]
      return run_callable(context, callable, splat) if callable
      raise Sass::SyntaxError.new("Undefined mixin '#{name}'.")
    end

    def run_callable(context, callable, splat)
      # TODO: test all calling convention stuff twice, once for static
      # and once for dynamic calls.
      desc = "#{callable.type.capitalize} #{callable.name}"
      downcase_desc = "#{callable.type} #{callable.name}"

      # All keywords are contained in splat.keywords for consistency,
      # even if there were no splats passed in.
      old_keywords_accessed = splat.keywords_accessed
      keywords = splat.keywords
      splat.keywords_accessed = old_keywords_accessed

      begin
        unless keywords.empty?
          unknown_args = Sass::Util.array_minus(keywords.keys,
            callable.args.map {|var| var.first.underscored_name})
          if callable.splat && unknown_args.include?(callable.splat.underscored_name)
            raise Sass::SyntaxError.new("Argument $#{callable.splat.name} of #{downcase_desc} " +
                                        "cannot be used as a named argument.")
          elsif unknown_args.any?
            description = unknown_args.length > 1 ? 'the following arguments:' : 'an argument named'
            raise Sass::SyntaxError.new("#{desc} doesn't have #{description} " +
                                        "#{unknown_args.map {|name| "$#{name}"}.join ', '}.")
          end
        end
      rescue Sass::SyntaxError => keyword_exception
      end

      # If there's no splat, raise the keyword exception immediately. The actual
      # raising happens in the ensure clause at the end of this function.
      return if keyword_exception && !callable.splat

      args = splat.to_a
      splat_sep = splat.separator

      if args.size > callable.args.size && !callable.splat
        extra_args_because_of_splat = splat && args.size - splat.to_a.size <= callable.args.size

        takes = callable.args.size
        passed = args.size
        message = "#{desc} takes #{takes} argument#{'s' unless takes == 1} " +
          "but #{passed} #{passed == 1 ? 'was' : 'were'} passed."
        raise Sass::SyntaxError.new(message) unless extra_args_because_of_splat
        # TODO: when the deprecation period is over, make this an error.
        Sass::Util.sass_warn("WARNING: #{message}\n" +
          stack.to_s.gsub(/^/m, " " * 8) + "\n" +
          "This will be an error in future versions of Sass.")
      end

      ruby_args = callable.args.zip(args[0...callable.args.length]).map do |(var, default), value|
        if value && keywords.has_key?(var.name)
          raise Sass::SyntaxError.new("#{desc} was passed argument $#{var.name} " +
                                      "both by position and by name.")
        end

        value ||= keywords.delete(var.name)
        raise Sass::SyntaxError.new("#{desc} is missing argument #{var.inspect}.") unless value
        value
      end

      if callable.splat
        rest = args[callable.args.length..-1] || []
        arg_list = Sass::Script::Value::ArgList.new(rest, keywords, splat_sep)
        ruby_args << arg_list
      end

      callable.run(context, ruby_args)
    rescue StandardError => e
    ensure
      # If there's a keyword exception, we don't want to throw it immediately,
      # because the invalid keywords may be part of a glob argument that should be
      # passed on to another function. So we only raise it if we reach the end of
      # this function *and* the keywords attached to the argument list glob object
      # haven't been accessed.
      #
      # The keyword exception takes precedence over any Sass errors, but not over
      # non-Sass exceptions.
      if keyword_exception &&
          !(arg_list && arg_list.keywords_accessed) &&
          (e.nil? || e.is_a?(Sass::SyntaxError))
        raise keyword_exception
      elsif e
        raise e
      end
    end
  end

  # The lexical environment for SassScript.
  # This keeps track of variable, mixin, and function definitions.
  #
  # A new environment is created for each level of Sass nesting.
  # This allows variables to be lexically scoped.
  # The new environment refers to the environment in the upper scope,
  # so it has access to variables defined in enclosing scopes,
  # but new variables are defined locally.
  #
  # Environment also keeps track of the {Engine} options
  # so that they can be made available to {Sass::Script::Functions}.
  class Environment < BaseEnvironment
    # The enclosing environment,
    # or nil if this is the global environment.
    #
    # @return [Environment]
    attr_reader :parent

    # variable
    # Script::Value
    inherited_hash_writer :var

    # mixin
    # Sass::Callable
    inherited_hash_writer :mixin

    # function
    # Sass::Callable
    inherited_hash_writer :function
  end

  # A read-only wrapper for a lexical environment for SassScript.
  class ReadOnlyEnvironment < BaseEnvironment
    # The read-only environment of the caller of this environment's mixin or function.
    #
    # @see BaseEnvironment#caller
    # @return {ReadOnlyEnvironment}
    def caller
      return @caller if @caller
      env = super
      @caller ||= env.is_a?(ReadOnlyEnvironment) ? env : ReadOnlyEnvironment.new(env, env.options)
    end

    # The read-only content passed to this environment.
    #
    # @see BaseEnvironment#content
    # @return {ReadOnlyEnvironment}
    def content
      return @content if @content
      env = super
      @content ||= env.is_a?(ReadOnlyEnvironment) ? env : ReadOnlyEnvironment.new(env, env.options)
    end
  end

  # An environment that can write to in-scope global variables, but doesn't
  # create new variables in the global scope. Useful for top-level control
  # directives.
  class SemiGlobalEnvironment < Environment
    def try_set_var(name, value)
      @vars ||= {}
      if @vars.include?(name)
        @vars[name] = value
        true
      elsif @parent
        @parent.try_set_var(name, value)
      else
        false
      end
    end
  end
end
