module DiasporaClient
  class WrongPermissionType < ArgumentError; end
  class WrongPermissionAccessType < ArgumentError; end
  class Permissions
    def initialize
      @permissions = {}
    end
    
    def get(type)
      @permissions[type]
    end
    alias_method :[], :get
    
    def set(type, access_type)
        unless available_types.include?(type)
          raise WrongPermissionType, "#{type} is not an available permission type. Available: #{available_types.join(", ")}"
        end
        unless available_access_types.include?(access_type)
          raise WrongPermissionAccessType, "#{access_type} is not an available permission access type. Available: #{available_access_types.join(", ")}"
        end
        
        @permissions[type] = access_type
    end
    alias_method :[]=, :set
    
    
    def manifest_array
      @permissions.collect { |type, access_type| {:type => type, :access => access_type} }
    end
    
    def all_scopes_string
      @permissions.keys.join(",")
    end
    
    private
    
    def available_types
      [:posts,:as_photos, :comments, :likes, :aspects, :profile, :people]
    end
    
    def available_access_types
      [:read, :write]
    end
  end
end
