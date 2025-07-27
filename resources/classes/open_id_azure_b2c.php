<?php  // July 27 2025 - Ardavan Hashemzadeh

class open_id_azure_b2c implements open_id_authenticator {

  	//
  	// OpenID Connect State Variables
  	//

    protected $client_id;
    protected $client_secret;
    protected $redirect_uri;
    protected $scope;
    protected $state;
    protected $discovery_url;
    protected $auth_endpoint;
    protected $token_endpoint;
    protected $userinfo_endpoint;
    protected $end_session_endpoint;

  	/**
  	 * When true, the global default settings are set to use a globally unique username
  	 * @var bool
  	 */
    protected $unique_username;

  	/**
  	 * When true, no errors will be thrown. When false, errors can be thrown to help with debugging
  	 * @var bool
  	 */
    protected $suppress_errors;

  	/**
  	 * Field name that contains the OpenID Connect field
  	 * @var string
  	 */
    protected $azure_field;

    /**
  	 * Field name that contains the users table field
  	 * @var string
  	 */
    protected $table_field;

  	/**
  	 * Set up URL parameters and object variables
  	 *
  	 * @param string $client_id     Your Client ID.
  	 * @param string $client_secret Your Client Secret.
  	 * @param string $redirect_uri  The redirect URI registered with Google.
  	 * @param string $scope         Space-separated scopes (default: "openid email profile").
  	 */
    public function __construct($scope = "openid email profile") {
        global $settings;

    		//
    		// Ensure we have a valid settings object
    		//
        if (!($settings instanceof settings)) {
            $settings = new settings([
                'database' => database::new(),
                'domain_uuid' => $_SESSION['domain_uuid'] ?? '',
                'user_uuid' => $_SESSION['user_uuid'] ?? '',
            ]);
        }

     		// Set the suppress errors with a default of true to avoid UI interruption
        $this->suppress_errors = $settings->get('open_id', 'suppress_errors', true);

     		// Set the variables from settings
        $this->client_id = $settings->get('open_id', 'azure_b2c_client_id');
        $this->client_secret = $settings->get('open_id', 'azure_b2c_client_secret');
        $this->redirect_uri = $settings->get('open_id', 'azure_b2c_redirect_uri');

        //
        // Replace the {$domain_name} placeholder for user in redirect_uri
        //
        if (str_contains($this->redirect_uri, '{$domain_name}')) {
            $this->redirect_uri = str_replace('{$domain_name}', $_SESSION['domain_name'], $this->redirect_uri);
        }

    		//
    		// Replace the {$plugin} placeholder for user
    		//
        if (str_contains($this->redirect_uri, '{$plugin}')) {
            $this->redirect_uri = str_replace('{$plugin}', self::class, $this->redirect_uri);
        }

    		// Get the field mapping for the OIDC email address to the user email address or username field in v_users table
        $mapping = $settings->get('open_id', 'azure_b2c_username_mapping');

     		// When errors are allowed and the field mapping is empty or has an equal sign throw an error
        if (!$this->suppress_errors && (empty($mapping) || !str_contains($mapping, '='))) {
            throw new \InvalidArgumentException('azure_username_mapping must be in the form azure_oidc_field=user_column');
        }

    		// Map the OpenID Connect (OIDC) field to the user table field to validate the user exists
        [$azure_field, $table_field] = explode('=', $mapping, 2);

        // Trim the whitespace for field names and store in the object
        $this->azure_field = trim($azure_field);
        $this->table_field = trim($table_field);

        // Test that users table field exists
        if (!$this->suppress_errors && !$settings->database()->column_exists(database::TABLE_PREFIX . 'users', $this->table_field)) {
            throw new \InvalidArgumentException("Users table field $this->table_field does not exist");
        }

        $tenant = $settings->get('open_id', 'azure_b2c_tenant');
        $policy = $settings->get('open_id', 'azure_b2c_policy');
        if (empty($tenant) || empty($policy)) {
            throw new \InvalidArgumentException('azure_tenant and azure_policy must be set');
        }

        $this->discovery_url = "https://{$tenant}.b2clogin.com/{$tenant}.onmicrosoft.com/{$policy}/v2.0/.well-known/openid-configuration";
        $this->scope = $scope;
    }

    public function authenticate(): array {
        $result = ["authorized" => false];
        $this->load_discovery();

        if (!isset($_GET['code'])) {
            if (!empty($_SESSION['open_id_authorize']) && $_SESSION['open_id_authorize']) {
                $_SESSION['open_id_authorize'] = false;
                die('unable to redirect');
            }

            $_SESSION['open_id_state'] = bin2hex(random_bytes(5));
            $_SESSION['open_id_code_verifier'] = bin2hex(random_bytes(50));
            $_SESSION['open_id_authorize'] = true;
            $_SESSION['open_id_action'] = 'open_id_azure_b2c';

            $authorize_url = $this->get_authorization_url();
            header('Location: ' . $authorize_url);
            exit();
        } else {
            $code = $_REQUEST['code'];
            $token = $this->exchange_code_for_token($code);

            if (isset($token['id_token'])) {
                $user_info = $this->decode_id_token($token['id_token']);

                if (isset($user_info[$this->azure_field])) {
                    global $database;
                    $sql = "SELECT user_uuid, username, u.domain_uuid domain_uuid, d.domain_name domain_name
                            FROM v_users u
                            LEFT JOIN v_domains d ON d.domain_uuid = u.domain_uuid
                            WHERE u.{$this->table_field} = :value
                            AND d.domain_uuid = :domain_uuid
                            AND user_enabled = 'true'
                            LIMIT 1";
                    $params = [
                      'value' => $user_info[$this->azure_field],
                      'domain_uuid' => $_SESSION['domain_uuid']
                    ];
                    $row = $database->select($sql, $params, 'row');

                    if ($row) {
                        
                        $result = array_merge($row, [
                                              "authorized" => true,
                                              "user_mail" => $user_info['email']
                                             ]);
                      $_SESSION['authorized'] = true;
                        
                    }
                }
            }
        }

        return $result;
    }

    protected function load_discovery(): void {
        $json = file_get_contents($this->discovery_url);
        $metadata = json_decode($json, true);
        $this->auth_endpoint = $metadata['authorization_endpoint'] ?? '';
        $this->token_endpoint = $metadata['token_endpoint'] ?? '';
        $this->userinfo_endpoint = $metadata['userinfo_endpoint'] ?? '';
        $this->end_session_endpoint = $metadata['end_session_endpoint'] ?? '';
    }

    protected function get_authorization_url(): string {
    		// Generate a state value for CSRF protection.
    		$this->state = $_SESSION['open_id_state'];
        $params = [
            'client_id' => $this->client_id,
            'response_type' => 'code',
            'redirect_uri' => $this->redirect_uri,
            'response_mode' => 'query',
            'scope' => $this->scope,
            'state' => $_SESSION['open_id_state'],
        ];
        return $this->auth_endpoint . '?' . http_build_query($params);
    }

    protected function exchange_code_for_token(string $code): array {
        $params = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'code' => $code,
            'redirect_uri' => $this->redirect_uri,
        ];

        $options = [
            'http' => [
                'header' => "Content-Type: application/x-www-form-urlencoded",
                'method' => 'POST',
                'content' => http_build_query($params),
            ],
        ];

        $context = stream_context_create($options);
        $response = file_get_contents($this->token_endpoint, false, $context);
        return json_decode($response, true);
    }

    protected function decode_id_token(string $id_token): array {
        $parts = explode('.', $id_token);
        if (count($parts) !== 3) return [];
        return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    }

    public static function get_banner_image(): string {
    		global $settings;
    		$azure_b2c_banner = $settings->get('open_id', 'azure_b2c_image', '');
    		$text = new text();
    		$text_array = $text->get();
    		$alt = $text_array['alt-banner'] ?? 'Sign-in Using Microsoft';
    		if (file_exists($azure_b2c_banner)) {
      			$file_handle = fopen($azure_b2c_banner, 'rb');
      			$data = base64_encode(fread($file_handle, 2182));
      			fclose($file_handle);
      			return "<img src='data:image/png;base64,$data' alt='$alt'/>";
    		}
    		return $alt;
  	}
}
