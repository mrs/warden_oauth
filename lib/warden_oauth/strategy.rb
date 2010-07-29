module Warden
  module OAuth2
    #
    # Holds all the main logic of the OAuth authentication, all the generated
    # OAuth classes will extend from this class
    #
    class Strategy < Warden::Strategies::Base
      extend StrategyBuilder

      ######################
      ### Strategy Logic ###
      ######################

      def self.user_finders
        (@_user_finders ||= {})
      end

      #
      #
      #
      def valid?
        true
      end

      #
      # Manages the OAuth authentication process, there can be 3 outcomes from this Strategy:
      # 1. The OAuth credentials are invalid and the FailureApp is called
      # 2. The OAuth credentials are valid, but there is no user associated to them. In this case
      #    the FailureApp is called, but the env['warden.options'][:oauth][:access_token] will be 
      #    available.
      # 3. The OAuth credentials are valid, and the user is authenticated successfuly
      #
      # @note
      # If you want to signup users with the twitter credentials, you can manage the creation of a new 
      # user in the FailureApp with the given access_token
      #
      def authenticate!
        if retrieve_oauth_token
          begin
            user_id = user_id_from_token
          rescue ::OAuth2::AccessDenied => e
            puts "User with access token #{retrieve_oauth_token} not found"
            logger.debug "User with access token #{retrieve_oauth_token} not found"
            delete_oauth_token
            fail!("User with access token not found")
            throw_error_with_oauth_info
          end

          user = find_user(user_id)
          if user.nil?
            puts "User with access token #{retrieve_oauth_token} not found with id #{user_id}"
            logger.debug "User with access token #{retrieve_oauth_token} not found with id #{user_id}"
            delete_oauth_token
            fail!("User with id not found")
            throw_error_with_oauth_info
          else
            success!(user)
          end
        end
      end

      def fail!(msg) #:nodoc:
        self.errors.add(service_param_name.to_sym, msg)
        super
      end

      ###################
      ### OAuth Logic ###
      ###################
      def self.validate_token!(raw_session, params)
        unless params['code']
	  access_token = raw_session[:oauth_token]
          
          token = token_instance(access_token)
          begin
            token.get('/me')
            true
          rescue ::OAuth2::AccessDenied => e
            begin
              refresh_token = raw_session[:refresh_token]
              token = client.web_server.refresh_access_token(refresh_token)
              raw_session[:oauth_token] = token.token
            rescue ::OAuth2::AccessDenied => e
              throw :warden
              throw_error_with_oauth_info
            end
          end
        end
      end

      def client
        @client ||= ::OAuth2::Client.new(config.client_id, config.client_secret, options)
      end

      def access_token
        @access_token ||= ::OAuth2::AccessToken.new(client, retrieve_oauth_token)
      end

      def self.token_instance(oauth_token)
        ::OAuth2::AccessToken.new(client, oauth_token)
      end

      def self.client
        ::OAuth2::Client.new(config.client_id, config.client_secret, options)
      end

      def retrieve_oauth_token
        session[:oauth_token] = cookies[:oauth_token] unless session[:oauth_token]
        session[:oauth_token]
      end

      def delete_oauth_token
        session[:oauth_token] = nil
        cookies[:oauth_token] = nil
      end

      def user_id_from_token
        json = access_token.get("/me")
        JSON.parse(json)["id"]
      end

      protected

      def find_user(user_id)
        raise RuntimeError.new(<<-ERROR_MESSAGE) unless self.respond_to?(:_find_user)

      You need to define a finder by access_token for this strategy.
      Write on the warden initializer the following code:
      Warden::OAuth2.user_finder(:     #{config.provider_name}     ) do |user_identifier|
        # Logic to get your user from an identifier
      end

        ERROR_MESSAGE
        self._find_user(user_id)
      end

      def throw_error_with_oauth_info
        throw(:warden, :oauth => {
                self.config.provider_name => {
                        :provider     => config.provider_name,
                        :access_token => access_token,
                        :client_id       => config.client_id,
                        :client_secret   => config.client_secret
                }
        })
      end

      def store_request_class_on_session
        session[:request_class]  = self.class.to_s
      end

      def service_param_name
        '%s_oauth' % config.provider_name
      end

      def config
        self.class.config
      end

      def self.config
        const_get("CONFIG")
      end

      def options
        self.class.options
      end

      def self.options
        # the client deletes stuff from the hash.
        # the clone call preserves all info in the original options
        const_get("OPTIONS").clone
      end

    end

  end
end
