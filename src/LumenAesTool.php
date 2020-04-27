<?php
/**
 * AES 加密解密服务组件。
 *
 * @author    YingMuzZ <huadyingmu@gmail.com>
 * @copyright © 2020 YingMuzZ
 * @version   v1.0
 */

namespace YingMuzZ\LumenAesComponent;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Config;

class LumenAesTool
{
    /**
     * redis防止重放攻击的键名。
     */
    const REPLAY_ATTACK_KEYS = 'replay_attack_keys:';

    /**
     * 防止重放攻击的时间；秒。
     */
    const LIMIT_TIME = 300;

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
     * 向量随机字符串。
     * @var string
     */
    protected $iv_hash;

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
        $this->offset = (int) $a_aes_config['offset'];
        $this->key = $a_aes_config['key'];
        $this->method = $a_aes_config['method'];
        $this->iv = $this->generateIV();
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

        return $this->iv_hash . $s_hash;
    }

    /**
     * hash解密方法。
     * @param string $hash Hash值
     * @return mixed
     */
    public function aesAppDecrypt(string $hash = '')
    {
        //获取向量
        $this->iv = substr($hash, $this->offset, $this->iv_length);
        Log::debug('AES IV:' . $this->iv);
        if (strlen($this->iv) != $this->iv_length) {
            throw new \Exception("向量长度验证失败!~");
        }
        //获取固定40位的盐
        $s_salt = substr($hash, 40, 40);
        Log::debug('AES SALT:' . $s_salt);
        //获取解密之前的字符串
        $s_hash_data = substr($hash, 80);
        Log::debug('AES HASH:' . $s_hash_data);
        //验证签名
        if (sha1($this->iv . $s_hash_data . $this->key) != $s_salt) {
            throw new \Exception("签名校验失败!~");
        }
        //防止重放攻击;设置盐值30分钟内唯一
        $b_flag = Redis::exists(static::REPLAY_ATTACK_KEYS . $s_salt);
        if (true == $b_flag) {
            throw new \Exception("重复请求!~");
        }
        Redis::set(static::REPLAY_ATTACK_KEYS . $s_salt, 1);
        Redis::expire(static::REPLAY_ATTACK_KEYS . $s_salt, static::LIMIT_TIME);

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
        Log::debug('hash:' . $s_hash);
        Log::debug('offset:' . $this->offset);
        $this->iv_hash = $s_hash;
        $s_iv = substr($s_hash, $this->offset, $iv_length);
        Log::debug('iv:' . $s_iv);
        if (strlen($s_iv) != $iv_length) {
            throw new \Exception("向量长度不匹配！~");
        }

        return $s_iv;
    }
}
