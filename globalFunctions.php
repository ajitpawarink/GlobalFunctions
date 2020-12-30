<?php

/**
 * Encrypts Decrypts file
 * @param string $mode The mode to encrypt or decrypt.
 * @param string $key key for encryption or decryption
 * @param string $inputFilePath path for input file
 * @param string $oputputFilePath path for output file
 * @return boolean returns true on successfull file conversion else flase
 * @throws Exception on receiving invalid mode except enc or dec
 */
function doCryptoFile( $mode, $key, $inputFilePath, $oputputFilePath ){
    $key = mb_convert_encoding($key, "UTF-8");
    $salt = implode( array_map("chr", [ -44, -5, -88, 82, 116, -8, -64, -93 ] ) );

    $IVbytes = NULL;
    
    $method = "AES-256-CBC";
 
    //creates a hash using key & salt with sha256 equivalent to PBKDF2WithHmacSHA256
    $hash = openssl_pbkdf2( $key, $salt, '256', '65556', 'sha256' );

    $data = file_get_contents( $inputFilePath );

    if( 'enc' == $mode ){
        $result = openssl_encrypt( $data, $method, $hash, OPENSSL_RAW_DATA, $IVbytes );
        $result = base64_encode( $IVbytes . $data );
    } elseif( 'dec' == $mode ) {
        $data = base64_decode( $data );
        $IVbytes = substr( $data, 0, 16 );
        $data = substr( $data, 16 );

        $result = openssl_decrypt( $data, $method, $hash, OPENSSL_RAW_DATA, $IVbytes );
    } else {
        throw new Exception( "Invalid Encryption mode." );
    }

    if( !$result ){
        throw new Exception( "Error encrypting/decrypting file : " . openssl_error_string() );
    }

    file_put_contents( $oputputFilePath, $result );
    return true;
}

/**
 * Encrypts Decrypts string
 * @param string $mode The mode to encrypt or decrypt.
 * @param string $key key for encryption or decryption
 * @param string $strInput input string for conversion
 * @return string|false The converted string on success or false on failure.
 * @throws Exception on receiving invalid mode except enc or dec
 */
function doCryptoString( $mode, $key, $strInput ){

    $key = mb_convert_encoding($key, "UTF-8");
    $salt = implode( array_map("chr", [ -44, -5, -88, 82, 116, -8, -64, -93 ] ) );
    
    $method = "AES-256-CBC";

    //creates a hash using key & salt with sha256 equivalent to PBKDF2WithHmacSHA256
    $hash = openssl_pbkdf2( $key, $salt, '256', '65556', 'sha256' );

    if( 'enc' == $mode ){
        $IVbytes = random_bytes(16);
        $strOputput = openssl_encrypt( $strInput, $method, $hash, OPENSSL_RAW_DATA, $IVbytes );
        $strOputput = base64url_encode(  $IVbytes . $strOputput );
    } elseif( 'dec' == $mode ) {
        $strInput = base64url_decode( $strInput );
        $IVbytes = substr( $strInput, 0, 16 );
        $strInput = substr( $strInput, 16 );
        $strOputput = openssl_decrypt( $strInput, $method, $hash, OPENSSL_RAW_DATA, $IVbytes );
    } else {
        throw new Exception( "Invalid Encryption mode." );
    }

    if( !$strOputput ){
        throw new Exception( "Error encrypting/decrypting file : " . openssl_error_string() );
    }
    return $strOputput;
}

function base64url_encode( $data ) {
    //Encode Base64 string and return the original data
    $b64 = base64_encode( $data );
    //Convert to Base64URL from Base64 by replacing “+” with “-” and “/” with “_”
    return strtr( $b64, '+/','-_' );
}

function base64url_decode( $data, $strict = false ) {
    // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
    $b64 = strtr($data, '-_', '+/');
    // Decode Base64 string and return the original data
    return base64_decode($b64, $strict);
}

//simple function to display data
function dig( $var ){
    echo '<pre>';
    print_r( $var );
    echo '</pre>';
}

function out( $var = 'Test' ){
    dig( $var );
    die;
}


?>
