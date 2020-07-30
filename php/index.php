<?php
ini_set('display_errors', 1);
error_reporting(1);

class webProxy{
    private $credentials = false;
    public $request = false;
    public $response = false;
    public function __construct($username=null, $password=null, $rename_headers=array()){
        $this->request = new stdClass();
        $this->response = new stdClass();
        $this->renameHeaders = $rename_headers;
        if(is_string($username) && is_string($password) && strlen($username) > 0 && strlen($password) > 0){
            $this->credentials = array('user' => $username, 'pass' => $password);
        }
        foreach(getallheaders() as $key => $value){
            $this->request->headers[strtolower($key)] = $value;
        }
        $this->encoded = isset($_GET['e']);
        $this->desbug = isset($_GET['d'])?intval($_GET['d']):0;
    }
    private function auth(){
        if($this->credentials){
            if(!isset($this->request->headers['x-authorization']) || strpos($this->request->headers['x-authorization'], 'Basic ') < 0){
                return false;
            }
            $cred = explode(':', @base64_decode(str_replace('Basic ', '', $this->request->headers['x-authorization'])), 2);
            if(!($cred[0] === $this->credentials['user'] && $cred[1] === $this->credentials['pass'])){
                return false;
            }
        }
        return true;
    }
    private function response($code, $body=null, $headers=array('Content-Type' => 'text/plain')){
    	http_response_code($code);
    
        if(is_array($headers)){
            foreach($headers as $name => $value){
                header($name.": ".$value);
            }
        }
        exit($body);
    }
    public function init(){
        if(!$this->auth()){
            $this->response(401, "not authorized");
        }
        if(!isset($this->request->headers['x-target']) || strlen($this->request->headers['x-target']) < 1){
            $this->response(400, 'bad request');
        }
        $this->request->target = $this->request->headers['x-target'];
        if($this->encoded){
            $this->request->target = base64_decode($this->request->target);
        }
        if(!filter_var($this->request->target, FILTER_VALIDATE_URL)){
            $this->response(400, 'URL \''.$this->request->target.'\' not valid');
        }
        $this->parseUrl = parse_url($this->request->target);
        unset($this->request->headers['x-target']);
        unset($this->request->headers['x-authorization']);
        $this->request->method = strtoupper($_SERVER['REQUEST_METHOD']);
        $this->request->body = file_get_contents('php://input');
        if($this->encoded){
            $this->request->body = base64_decode($this->request->body);
            if(isset($this->request->headers['cookie'])){
                $this->request->headers['cookie'] = @base64_decode($this->request->headers['cookie']);
            }
        }

        $remove = array();
        if(isset($this->request->headers['x-remove'])){
            $remove = explode(',', @base64_decode($this->request->headers['x-remove']));
            if(!is_array($remove)){
                $remove = array();
            }else{
                for($j = 0; $j < sizeof($remove); $j++){
                    $remove[$j] = str_replace(' ', '', $remove[$j]);
                }
            }
        }
        unset($this->request->headers['host']);
        unset($this->request->headers['connection']);
        unset($this->request->headers['x-remove']);
        unset($this->request->headers['content-length']);
        unset($this->request->headers['accept-encoding']);
        foreach($remove as $value){
            if(isset($this->request->headers[$value])){
                unset($this->request->headers[$value]);
            }
        }
        $remove = array();
        if(isset($this->request->headers['x-remove-response'])){
            $remove = explode(',', @base64_decode($this->request->headers['x-remove-response']));
            if(!is_array($remove)){
                $remove = array();
            }else{
                for($j = 0; $j < sizeof($remove); $j++){
                    $remove[$j] = str_replace(' ', '', $remove[$j]);
                }
            }
        }
        $this->removeHeaders = $remove;
        $this->request();
        $this->prepareHeaders();
        $this->build();
    }
    private function buildHeaders($headers){
        $build = '';
        foreach($headers as $name => $value){
            $build .= ' -H "'.$name.": ".$value.'"';
        }
        return substr($build, 1);
    }
    public function request(){
        $command = new stdClass();
        $command->data = '';
        $command->headers = $this->buildHeaders($this->request->headers);
        if(strlen($this->request->body) > 0){
            $command->data = '--data "'.$this->request->body.'"';
        }
        $command->call = sprintf('curl -k -D - --request %s "%s" %s %s', $this->request->method, $this->request->target, $command->headers, $command->data);
        ob_start();
        if($this->desbug == 1){
            $this->response(200, $command->call);
        }
        passthru($command->call);
        $command->response = ob_get_clean();

        if(strlen($command->response) < 1){
            $this->response(500, "Failed to connect to '".$this->request->target."'");
        }
        if($this->desbug == 2){
            $this->response(200, $command->response);
        }
        $out = preg_split('/(\r?\n){2}/', $command->response, 2);
        $this->response->body = $out[1];
        
        $this->response->status = 0;
        if(preg_match('/\s\d{3}/', $out[0], $sc)){
            $this->response->status = intval($sc[0]);
        }
        $out = explode(PHP_EOL, $out[0]);
        $this->response->headers = array();
        foreach($out as $header){
            $header = trim($header);
            $header = explode(': ', $header, 2);
            if(sizeof($header)<2||strlen($header[0])<1||strlen($header[1])<1){
                continue;
            }
            $header[0] = strtolower($header[0]);
            $this->response->headers[$header[0]] = $header[1];
        }
        unset($this->response->headers['content-length']);
    }
    public function prepareHeaders(){
        $tmp = array();
        foreach($this->response->headers as $name => $value){
            if(in_array($name, $this->renameHeaders)){
                $tmp['p-'.$name] = $value;
            }
            elseif(!in_array($name, $this->removeHeaders)){
                $tmp[$name] = $value;
            }
        }
        $this->response->headers = $tmp;
        if(isset($this->response->headers['location'])){
            if(preg_match('(^https:\/\/|^http:\/\/)', $this->response->headers['location'])){
                if(preg_match('/teste-localhost\.com\.br*$/', parse_url($this->response->headers['location'], PHP_URL_HOST))){
                    $this->response->headers['location'] = str_replace(parse_url($this->response->headers['location'], PHP_URL_HOST), $this->parseUrl['host'], $this->response->headers['location']);
                }
            }
            else{
                if(strpos($this->response->headers['location'], '/') === false){
                    $this->response->headers['location'] = '/'.$this->response->headers['location'];
                }
                $this->response->headers['location'] = $this->parseUrl['scheme'].'://'.$this->parseUrl['host'].$this->response->headers['location'];                
            }
            $this->response->headers['location'] = base64_encode($this->response->headers['location']);
        }
    }
    public function build(){
        foreach($this->response->headers as $name => $value){
            header($name.": ".$value);
        }
        
        $this->response($this->response->status, $this->response->body, false);
    }
    public function test($method, $url, $body, $headers){
        $this->request->target = $url;
        $this->request->method = strtoupper($method);
        $this->request->headers = $headers;
        $this->request->body = $body;
    }
}

$proxy = new webProxy('webproxy','7f&KFK)33', array('server','x-xss-protection','x-powered-by','x-frame-options','date','connection','transfer-encoding'));
$proxy->init();
