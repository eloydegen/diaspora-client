module DiasporaClient
  class NotAuthorizedException < ArgumentError; end
  class Api
    def initialize(user, opts={})
      unless user && user.access_token && @token = user.access_token.token
        raise NotAuthorizedException, "Can't retrive access token via #{user}"
      end
      version = opts.delete(:version)
      @prefix = version ? '/api/'+version.to_s+'/' : ''
    end
    
    [:get, :post, :put, :delete].each do |method|
      define_method method do |*args|
        begin
          args[0] = @prefix+args[0]
          result = JSON.parse(@token.send(method, *args).body)
           if result.respond_to?(:deep_symbolize_keys)
            result = result.deep_symbolize_keys
           elsif result.respond_to?(:symbolize_keys)
            result = result.symbolize_keys
           end
           result
        rescue OAuth2::Error => e
          {:error => e.response.body}
        end
      end
    end
  end
end
