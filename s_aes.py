"""
S-AES算法实现
基于《密码编码学与网络安全》第8版附录D的简化AES算法
"""

class SAES:
    """
    S-AES算法实现类
    支持16位分组长度和16位密钥的加密解密
    """

    # S盒
    S_BOX = [
        [9, 4, 10, 11],
        [13, 1, 8, 5],
        [6, 2, 0, 3],
        [12, 14, 15, 7]
    ]

    # 逆S盒 - 16元素查找表
    # INV_S_BOX[y] = x，其中S[x] = y
    INV_S_BOX = [
        10,  # 0 -> 10
        5,   # 1 -> 5
        9,   # 2 -> 9
        11,  # 3 -> 11
        1,   # 4 -> 1
        7,   # 5 -> 7
        8,   # 6 -> 8
        15,  # 7 -> 15
        6,   # 8 -> 6
        0,   # 9 -> 0
        2,   # 10 -> 2
        3,   # 11 -> 3
        12,  # 12 -> 12
        4,   # 13 -> 4
        13,  # 14 -> 13
        14   # 15 -> 14
    ]

    # 列混淆矩阵
    MIX_MATRIX = [
        [1, 4],
        [4, 1]
    ]

    # 逆列混淆矩阵
    INV_MIX_MATRIX = [
        [9, 2],
        [2, 9]
    ]

    # 轮常量
    RC = [1, 2, 4, 8]

    def __init__(self, key_hex=None):
        """
        初始化S-AES算法

        Args:
            key_hex (str): 16位密钥的16进制字符串，如"0123"
        """
        if key_hex:
            self.key = self._hex_to_state(key_hex)
        else:
            # 默认密钥 (16位密钥用4个16进制字符表示)
            self.key = self._hex_to_state("0123")

        # 生成轮密钥
        self.round_keys = self._key_expansion()

    def _hex_to_state(self, hex_str):
        """
        将16进制字符串转换为2x2状态矩阵

        Args:
            hex_str (str): 4位16进制字符串（16位数据）

        Returns:
            list: 2x2状态矩阵
        """
        if len(hex_str) != 4:
            raise ValueError("密钥或明文必须是4位16进制数（16位数据）")

        state = []
        for i in range(2):
            row = []
            for j in range(2):
                # 将16进制转换为4位二进制，然后转换为整数
                hex_val = hex_str[2*i + j]
                row.append(int(hex_val, 16))
            state.append(row)
        return state

    def _state_to_hex(self, state):
        """
        将2x2状态矩阵转换为16进制字符串

        Args:
            state (list): 2x2状态矩阵

        Returns:
            str: 4位16进制字符串
        """
        hex_str = ""
        for i in range(2):
            for j in range(2):
                hex_str += hex(state[i][j])[2:].upper()
        return hex_str

    def _sub_nibbles(self, state, inverse=False):
        """
        字节替换

        Args:
            state (list): 2x2状态矩阵
            inverse (bool): 是否使用逆S盒

        Returns:
            list: 替换后的状态矩阵
        """
        if inverse:
            # 逆S盒使用16个元素的查找表
            new_state = [[0, 0], [0, 0]]
            for i in range(2):
                for j in range(2):
                    val = state[i][j]
                    new_state[i][j] = self.INV_S_BOX[val]
        else:
            # 正向S盒使用4x4矩阵
            new_state = [[0, 0], [0, 0]]
            for i in range(2):
                for j in range(2):
                    val = state[i][j]
                    # 将4位数转换为行和列索引
                    row = (val >> 2) & 0x3  # 高2位
                    col = val & 0x3         # 低2位
                    new_state[i][j] = self.S_BOX[row][col]

        return new_state

    def _shift_rows(self, state, inverse=False):
        """
        行移位

        Args:
            state (list): 2x2状态矩阵
            inverse (bool): 是否逆操作

        Returns:
            list: 移位后的状态矩阵
        """
        # 对于2x2矩阵，左移和右移是逆操作
        if inverse:
            # 逆行移位：第1行右移1位 (交换两个元素)
            return [
                [state[0][0], state[0][1]],
                [state[1][1], state[1][0]]
            ]
        else:
            # 行移位：第1行左移1位 (交换两个元素)
            return [
                [state[0][0], state[0][1]],
                [state[1][1], state[1][0]]
            ]

    def _mix_columns(self, state, inverse=False):
        """
        列混淆

        Args:
            state (list): 2x2状态矩阵
            inverse (bool): 是否使用逆矩阵

        Returns:
            list: 列混淆后的状态矩阵
        """
        matrix = self.INV_MIX_MATRIX if inverse else self.MIX_MATRIX
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                # GF(16)上的乘法
                sum_val = 0
                for k in range(2):
                    sum_val ^= self._gf16_multiply(state[k][j], matrix[i][k])
                new_state[i][j] = sum_val

        return new_state

    def _gf16_multiply(self, a, b):
        """
        GF(16)上的乘法，使用左移和异或实现

        Args:
            a (int): 第一个操作数
            b (int): 第二个操作数

        Returns:
            int: 乘法结果
        """
        result = 0
        while b > 0:
            if b & 1:
                result ^= a
            temp = a << 1
            if temp & 0x10:  # 如果超过16，模x^4 + x + 1
                temp ^= 0x13  # 10011b (x^4 + x + 1的本原多项式)
            a = temp & 0xF
            b >>= 1
        return result

    def _add_round_key(self, state, round_key):
        """
        轮密钥加

        Args:
            state (list): 状态矩阵
            round_key (list): 轮密钥

        Returns:
            list: 异或后的状态矩阵
        """
        new_state = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ round_key[i][j]
        return new_state

    def _key_expansion(self):
        """
        密钥扩展算法

        Returns:
            list: 包含所有轮密钥的列表
        """
        # 将密钥转换为4个4位字：w0, w1, w2, w3
        w = []
        for i in range(2):
            for j in range(2):
                w.append(self.key[i][j])

        # 生成w4和w5
        # w4 = w0 ⊕ g(w2, RC[0])
        g_w2 = self._g_function(w[2], 0)
        w4 = w[0] ^ g_w2
        
        # w5 = w1 ⊕ w4
        w5 = w[1] ^ w4
        
        # 生成w6和w7
        # w6 = w2 ⊕ g(w4, RC[1])
        g_w4 = self._g_function(w4, 1)
        w6 = w[2] ^ g_w4
        
        # w7 = w3 ⊕ w6
        w7 = w[3] ^ w6

        # 生成轮密钥 (每个轮密钥都是2x2的矩阵)
        round_keys = []
        
        # 第0轮密钥: w0w1w2w3 (原始密钥)
        round_keys.append([[w[0], w[1]], [w[2], w[3]]])
        
        # 第1轮密钥: w4w5w6w7
        round_keys.append([[w4, w5], [w6, w7]])
        
        # 第2轮密钥: w6w7w4w5
        round_keys.append([[w6, w7], [w4, w5]])

        return round_keys

    def encrypt(self, plaintext_hex):
        """
        S-AES加密

        Args:
            plaintext_hex (str): 16位明文的16进制字符串

        Returns:
            str: 16位密文的16进制字符串
        """
        state = self._hex_to_state(plaintext_hex)

        # 初始轮密钥加
        state = self._add_round_key(state, self.round_keys[0])

        # 第一轮
        state = self._sub_nibbles(state)
        state = self._shift_rows(state)
        state = self._mix_columns(state)
        state = self._add_round_key(state, self.round_keys[1])

        # 第二轮（最后一轮不进行列混淆）
        state = self._sub_nibbles(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[2])

        return self._state_to_hex(state)

    def decrypt(self, ciphertext_hex):
        """
        S-AES解密

        Args:
            ciphertext_hex (str): 16位密文的16进制字符串

        Returns:
            str: 16位明文的16进制字符串
        """
        state = self._hex_to_state(ciphertext_hex)

        # 初始轮密钥加（K2）
        state = self._add_round_key(state, self.round_keys[2])

        # 第2轮逆
        state = self._shift_rows(state, inverse=True)
        state = self._sub_nibbles(state, inverse=True)
        state = self._add_round_key(state, self.round_keys[1])

        # 第1轮逆
        state = self._mix_columns(state, inverse=True)
        state = self._shift_rows(state, inverse=True)
        state = self._sub_nibbles(state, inverse=True)
        state = self._add_round_key(state, self.round_keys[0])

        return self._state_to_hex(state)

    def _g_function(self, word, round_num):
        """
        g函数：对4位字进行变换

        Args:
            word (int): 4位输入字
            round_num (int): 轮数

        Returns:
            int: 变换后的4位字
        """
        # 字节替换
        row = (word >> 2) & 0x3  # 高2位
        col = word & 0x3         # 低2位
        substituted = self.S_BOX[row][col]

        # 与轮常量异或
        result = substituted ^ self.RC[round_num]

        return result


class DoubleSAES:
    """双重S-AES加密实现"""
    
    def __init__(self, key1, key2):
        self.saes1 = SAES(key1)
        self.saes2 = SAES(key2)
    
    def encrypt(self, plaintext_hex):
        """双重加密：E(K2, E(K1, plaintext))"""
        return self.saes2.encrypt(self.saes1.encrypt(plaintext_hex))
    
    def decrypt(self, ciphertext_hex):
        """双重解密：D(K1, D(K2, ciphertext))"""
        return self.saes1.decrypt(self.saes2.decrypt(ciphertext_hex))


class TripleSAES:
    """三重S-AES加密实现"""
    
    def __init__(self, key1, key2, key3, mode="EDE"):
        self.saes1 = SAES(key1)
        self.saes2 = SAES(key2)
        self.saes3 = SAES(key3)
        self.mode = mode
    
    def encrypt(self, plaintext_hex):
        """三重加密"""
        if self.mode == "EDE":
            # EDE模式：E(K1, D(K2, E(K1, plaintext)))
            temp = self.saes1.encrypt(plaintext_hex)
            temp = self.saes2.decrypt(temp)
            return self.saes3.encrypt(temp)
        else:  # EEE模式
            # EEE模式：E(K3, E(K2, E(K1, plaintext)))
            temp = self.saes1.encrypt(plaintext_hex)
            temp = self.saes2.encrypt(temp)
            return self.saes3.encrypt(temp)
    
    def decrypt(self, ciphertext_hex):
        """三重解密"""
        if self.mode == "EDE":
            # EDE模式解密：D(K1, E(K2, D(K3, ciphertext)))
            temp = self.saes3.decrypt(ciphertext_hex)
            temp = self.saes2.encrypt(temp)
            return self.saes1.decrypt(temp)
        else:  # EEE模式
            # EEE模式解密：D(K1, D(K2, D(K3, ciphertext)))
            temp = self.saes3.decrypt(ciphertext_hex)
            temp = self.saes2.decrypt(temp)
            return self.saes1.decrypt(temp)


class MeetInTheMiddleAttack:
    """中间相遇攻击"""
    
    def __init__(self):
        self.pairs = []
    
    def add_pair(self, plaintext, ciphertext):
        """添加已知明密文对"""
        self.pairs.append((plaintext, ciphertext))
    
    @property
    def attack(self):
        """执行中间相遇攻击"""
        return self.attack_limited(0x10000)  # 完整搜索

    def attack_limited(self, max_keys=256):
        """执行中间相遇攻击 - 限制搜索空间"""
        if not self.pairs:
            return None, None

        # 对每个明文-密文对尝试攻击
        for plaintext, ciphertext in self.pairs:
            # 生成可能的密钥1，加密明文
            forward_table = {}
            for k1 in range(min(max_keys, 0x10000)):  # 限制搜索空间
                key1_hex = format(k1, '04X')
                saes1 = SAES(key1_hex)
                intermediate = saes1.encrypt(plaintext)
                if intermediate not in forward_table:  # 只保留第一个找到的密钥
                    forward_table[intermediate] = key1_hex

            # 生成可能的密钥2，解密密文
            for k2 in range(min(max_keys, 0x10000)):  # 限制搜索空间
                key2_hex = format(k2, '04X')
                saes2 = SAES(key2_hex)
                intermediate = saes2.decrypt(ciphertext)

                if intermediate in forward_table:
                    found_k1 = forward_table[intermediate]
                    # 验证找到的密钥对是否正确
                    if self.verify_key(found_k1, key2_hex):
                        return found_k1, key2_hex

        return None, None
    
    def verify_key(self, key1, key2):
        """验证密钥是否正确"""
        double_saes = DoubleSAES(key1, key2)
        for plaintext, ciphertext in self.pairs:
            if double_saes.encrypt(plaintext) != ciphertext:
                return False
        return True


class SAES_CBC:
    """S-AES CBC模式"""
    
    def __init__(self, key, iv=None):
        self.saes = SAES(key)
        if iv:
            self.iv = self._hex_to_state(iv)
        else:
            # 生成随机IV
            import random
            self.iv = [[random.randint(0, 15), random.randint(0, 15)],
                      [random.randint(0, 15), random.randint(0, 15)]]
    
    def _hex_to_state(self, hex_str):
        """将16进制字符串转换为2x2状态矩阵"""
        state = []
        for i in range(2):
            row = []
            for j in range(2):
                hex_val = hex_str[2*i + j]
                row.append(int(hex_val, 16))
            state.append(row)
        return state
    
    def _state_to_hex(self, state):
        """将2x2状态矩阵转换为16进制字符串"""
        hex_str = ""
        for i in range(2):
            for j in range(2):
                hex_str += hex(state[i][j])[2:].upper()
        return hex_str
    
    def encrypt(self, plaintext_hex):
        """CBC模式加密"""
        blocks = [plaintext_hex[i:i+4] for i in range(0, len(plaintext_hex), 4)]
        ciphertext_blocks = []
        prev_block = self.iv

        for block in blocks:
            # 填充到4个字符
            block = block.ljust(4, '0')
            state = self._hex_to_state(block)

            # 与前一个密文块异或
            xor_state = [[0, 0], [0, 0]]
            for i in range(2):
                for j in range(2):
                    xor_state[i][j] = state[i][j] ^ prev_block[i][j]

            # 加密
            ciphertext_hex = self.saes.encrypt(self._state_to_hex(xor_state))
            ciphertext_blocks.append(ciphertext_hex)
            prev_block = self._hex_to_state(ciphertext_hex)

        return ''.join(ciphertext_blocks)
    
    def decrypt(self, ciphertext_hex):
        """CBC模式解密"""
        blocks = [ciphertext_hex[i:i+4] for i in range(0, len(ciphertext_hex), 4)]
        plaintext_blocks = []
        prev_block = self.iv

        for block in blocks:
            # 解密
            decrypted_hex = self.saes.decrypt(block)
            decrypted_state = self._hex_to_state(decrypted_hex)

            # 与前一个密文块异或
            xor_state = [[0, 0], [0, 0]]
            for i in range(2):
                for j in range(2):
                    xor_state[i][j] = decrypted_state[i][j] ^ prev_block[i][j]

            plaintext_blocks.append(self._state_to_hex(xor_state))
            prev_block = self._hex_to_state(block)

        # 合并所有块并去除填充的'0'
        result = ''.join(plaintext_blocks)
        return result.rstrip('0')
    
    def get_iv_hex(self):
        """获取初始向量的16进制字符串"""
        return self._state_to_hex(self.iv)


def run_all_tests():
    """运行所有测试"""
    print("运行S-AES测试...")
    print("=" * 60)
    
    # 基本加解密测试
    saes = SAES("0123")
    plaintext = "ABCD"
    ciphertext = saes.encrypt(plaintext)
    decrypted = saes.decrypt(ciphertext)
    
    print(f"明文: {plaintext}")
    print(f"密文: {ciphertext}")
    print(f"解密: {decrypted}")
    print(f"匹配: {plaintext == decrypted}")
    print("=" * 60)
