var oauthSignature=require('oauth-signature');
var querystring=require('querystring');
var fs=require('fs');
var http=require('https');
var date=new Date;
var request=require('request');
var httpServ=require('http');
var urlParse=require('url');
NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
              'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
              'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
              'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
              '4','5','6','7','8','9'];

function getNonce(nonceSize) {
   var result = [];
   var chars= NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;

   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
}
var getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
}

module.exports=function AuthTwitt(url,path,method,oauth_param,dop_param,callback)
{
	var httpMethod=method;
	var parameters=
	{
		oauth_consumer_key:oauth_param.consumer_key,
		oauth_nonce: getNonce(36),
		oauth_signature_method:'HMAC-SHA1',
		oauth_timestamp: getTimestamp(),
		oauth_version:oauth_param.version,
		oauth_token:oauth_param.token,
		oauth_callback:oauth_param.callback
	}
	if (dop_param)
	{
	path+='?';
	var chk=false;
	for(param in dop_param)
		{
			parameters[param]=dop_param[param];
			if (chk==false)
			{
				path+=param+'='+parameters[param];
				chk=true;
			}
			else 
			{
				path+='&'+param+'='+parameters[param];
			}
		}
	}
	
	var encodedSignature = oauthSignature.generate(httpMethod, url+path, parameters, oauth_param.consumer_secret, oauth_param.token_secret);
	var signature = oauthSignature.generate(httpMethod, url+path, parameters, oauth_param.consumer_secret, oauth_param.token_secret,
		{ encodeSignature: true});
	parameters.oauth_signature=signature;
	
		var reqs='OAuth ';
		for(param in parameters)
		{
			reqs+=param+'=\"'+parameters[param]+'\", ';
			
		}
	  var options = {
	  key: fs.readFileSync('key.pem'),
	  hostname: urlParse.parse(url).hostname,
	  path: path,
	  method: method,
	  headers: 
			{
				//'Content-Type': 'application/x-www-form-urlencoded',
				Authorization:reqs
			}
	};
	var request = http.request(options, function(response) {
			console.log(options);
			fs.writeFileSync('log.txt',options.headers.Authorization);
			var data='';
			response.on("data", function(chunk) {
					data+=chunk;
					});
			response.on("end",function(){callback(data)});
})
		request.end();
}




