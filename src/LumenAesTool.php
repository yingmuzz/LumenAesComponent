<?php
/**
 * AES 加密解密服务组件。
 *
 * @author    YingMuzZ <huadyingmu@gmail.com>
 * @copyright © 2020 YingMuzZ
 * @version   v1.0
 */

namespace YingMuzZ\LumenAesComponent;

use Illuminate\Support\Facades\Config;

class LumenAesTool
{
    /**
     * 加密算法。
     * @var string
     */
    protected $method;

    /**
     * 秘钥。
     * @var string
     */
    protected $key;

    /**
     * 向量。
     * @var string
     */
    protected $iv;

    /**
     * 向量长度。
     * @var int
     */
    protected $iv_length;

    /**
     * 偏移量。
     * @var int
     */
    protected $offset;

    public function __construct($version = '')
    {
        $a_aes_config = Config::get('aes.' . $version);
        if (null == $a_aes_config || !is_array($a_aes_config)) {
            throw new \Exception('配置未找到！~');
        } elseif (!isset($a_aes_config['key']) || 32 !== strlen($a_aes_config['key'])) {
            throw new \Exception('秘钥长度不匹配！~');
        } elseif (!isset($a_aes_config['offset']) || ((int) $a_aes_config['offset']) <= 0 || ((int) $a_aes_config['offset']) >= 24) {
            throw new \Exception('偏移量配置错误！~');
        }
        $this->key = $a_aes_config['key'];
        $this->method = $a_aes_config['method'];
        $this->iv = $this->generateIV();
        $this->offset = (int) $a_aes_config['offset'];
    }

    /**
     * openssl aes 加密。
     * @param  string $data 待加密内容
     * @return mixed
     */
    public function aesAppEncrypt(string $data = '')
    {
        if ('' == $data) {
            throw new \Exception("待加密字符串错误！~");
        }
        //加密字符串并使用base64编码
        $s_hash = base64_encode(openssl_encrypt($data, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv));
        //加入验签盐值
        $s_salt = sha1($this->iv . $s_hash . $this->key);
        //偏移字符串（随机）
        $s_offset_str = sha1(uniqid(true) . $this->iv . $this->key . microtime(true));
        //生成偏移开始字符串
        $s_offset_start = substr($s_offset_str, strlen($s_offset_str) - $this->offset - 1, $this->offset);
        //生成偏移结束字符串
        $s_offset_end = substr(sha1($this->iv . microtime(true) . uniqid(true)), 0, strlen($s_offset_str) - $this->offset);

        return $s_offset_end . $this->iv . $s_salt . $s_offset_start . $s_hash;
    }

    /**
     * hash解密方法。
     * @param string $hash Hash值
     * @return mixed
     */
    public function aesAppDecrypt(string $hash = '')
    {
        //去除首混淆字符。
        $s_new_hash = substr($hash, 40 - $this->offset);
        //获取向量
        $this->iv = substr($s_new_hash, 0, $this->iv_length);
        if (strlen($this->iv) != $this->iv_length) {
            throw new \Exception("向量长度验证失败!~");
        }
        //获取固定40位的盐
        $s_salt = substr($s_new_hash, $this->iv_length, 40);
        //获取解密之前的字符串
        $s_hash_data = substr($s_new_hash, $this->iv_length + 40 + $this->offset);
        //验证签名
        if (sha1($this->iv . $s_hash_data . $this->key) != $s_salt) {
            throw new \Exception("签名校验失败!~");
        }
        //解密数据
        $s_data = openssl_decrypt(base64_decode($s_hash_data), $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);

        return $s_data;
    }

    /**
     * 根据当前加密类型长度生成随机向量。
     * @return mixed
     */
    protected function generateIV()
    {
        if (!function_exists('openssl_cipher_iv_length')) {
            throw new \Exception("openssl_cipher_iv_length 方法不存在！~");
        }
        //获取向量字符串长度
        $iv_length = openssl_cipher_iv_length($this->method);
        if (false == $iv_length || 0 >= $iv_length || 16 < $iv_length) {
            throw new \Exception("向量长度获取失败！~");
        }
        $this->iv_length = $iv_length;
        //生成随机字符串
        $s_hash = sha1(microtime(true) . $this->key . uniqid(true));
        //从随机字符串中取出向量
        $s_iv = substr($s_hash, rand(2, 20), $iv_length);
        if (strlen($s_iv) != $iv_length) {
            throw new \Exception("向量长度不匹配！~");
        }

        return $s_iv;
    }
}
