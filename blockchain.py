# blockchain.py - 完整优化版
import hashlib
import json
import time
import threading
import socket
import logging
import uuid
from flask import Flask, jsonify, request, render_template
from collections import defaultdict

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('blockchain.log')
    ]
)

class Blockchain:
    def __init__(self, port):
        self.chain = []
        self.pending_transactions = {}  # 待确认交易
        self.nodes = set()
        self.node_names = {}  # 节点名称映射 {node_id: name}
        self.wallets = defaultdict(lambda: {
            'total': 100,
            'locked': 0,
            'available': 100
        })
        self.node_id = str(port)  # 使用端口号作为节点ID
        self.node_name = f"节点-{port}"  # 默认节点名称
        self.lock = threading.Lock()
        self.mining_lock = threading.Lock()
        self.port = port
        self.last_update_time = time.time()
        
        # 创建创世区块
        self.create_genesis_block()
        logging.info(f"Blockchain initialized with node ID: {self.node_id}")
        # 初始计算余额
        self.recalculate_balances()

    def create_genesis_block(self):
        """创建创世区块"""
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'transactions': [{
                'sender': "0",
                'recipient': "GENESIS",
                'amount': 0,
                'signature': "genesis_signature"
            }],
            'proof': 100,
            'previous_hash': "0",
            'hash': "genesis_hash"
        }
        self.chain.append(genesis_block)

    def register_node(self, address):
        """
        添加新节点到节点列表
        :param address: 节点地址，如 '192.168.1.5:5000'
        """
        # 移除协议部分如果存在
        if 'http://' in address:
            address = address.replace('http://', '')
        elif 'https://' in address:
            address = address.replace('https://', '')
        
        # 添加到节点集合
        if address not in self.nodes and address != f"127.0.0.1:{self.port}":
            self.nodes.add(address)
            logging.info(f"Registered new node: {address}")
            return True
        return False

    def update_node_name(self, node_id, new_name):
        """更新节点名称"""
        with self.lock:
            # 检查名称是否已被使用
            if new_name in self.node_names.values() and self.node_names.get(node_id) != new_name:
                return False, "名称已被使用"
            
            self.node_names[node_id] = new_name
            return True, "名称更新成功"

    def valid_chain(self, chain):
        """检查区块链是否有效"""
        if not chain or len(chain) == 0:
            return False
            
        # 验证创世区块
        genesis = chain[0]
        if genesis['index'] != 0 or genesis['previous_hash'] != "0":
            return False
            
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            
            # 检查区块哈希
            if block.get('previous_hash') != self.hash(last_block):
                return False
            
            # 检查工作量证明
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False
            
            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """共识算法：用网络中最长的链替换当前链"""
        if not self.nodes:
            return False
            
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            try:
                url = f"http://{node}/chain"
                response = self.send_request(url, timeout=2)
                if response and response.get('status_code') == 200:
                    chain_data = response.get('json', {})
                    length = chain_data.get('length', 0)
                    chain = chain_data.get('chain', [])
                    
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except:
                continue

        if new_chain:
            self.chain = new_chain
            self.recalculate_balances()
            self.last_update_time = time.time()
            return True
        
        return False

    def recalculate_balances(self):
        """重新计算所有钱包余额"""
        # 重置所有余额
        for addr in self.wallets:
            self.wallets[addr] = {
                'total': 100,
                'locked': 0,
                'available': 100
            }
        
        # 处理节点名称
        all_node_ids = {self.node_id}
        for node in self.nodes:
            node_id = node.split(':')[-1]
            all_node_ids.add(node_id)
            if node_id not in self.node_names:
                self.node_names[node_id] = f"节点-{node_id}"
        
        # 初始余额
        for addr in all_node_ids:
            self.wallets[addr]['total'] = 100
            self.wallets[addr]['available'] = 100
        
        # 计算交易影响
        for block in self.chain:
            if block['index'] == 0:
                continue
                
            for trans in block.get('transactions', []):
                sender = trans.get('sender', '')
                recipient = trans.get('recipient', '')
                amount = trans.get('amount', 0)
                
                if sender == "0":  # 挖矿奖励
                    if recipient in self.wallets:
                        self.wallets[recipient]['total'] += amount
                        self.wallets[recipient]['available'] += amount
                    continue
                
                if sender in self.wallets:
                    self.wallets[sender]['total'] -= amount
                    self.wallets[sender]['available'] -= amount
                
                if recipient in self.wallets:
                    self.wallets[recipient]['total'] += amount
                    self.wallets[recipient]['available'] += amount
        
        # 计算锁定资金（待处理交易）
        for txid, tx in self.pending_transactions.items():
            if tx['status'] == 'pending' and tx['sender'] in self.wallets:
                self.wallets[tx['sender']]['locked'] += tx['amount']
                self.wallets[tx['sender']]['available'] = max(0, self.wallets[tx['sender']]['available'] - tx['amount'])

    def new_block(self, proof, previous_hash=None):
        """创建新区块"""
        with self.lock:
            # 收集已确认的交易
            confirmed_transactions = []
            for txid, tx in list(self.pending_transactions.items()):
                if tx['status'] == 'confirmed':
                    confirmed_transactions.append(tx['data'])
                    del self.pending_transactions[txid]
            
            # 添加挖矿奖励
            confirmed_transactions.append({
                'sender': "0",
                'recipient': self.node_id,
                'amount': 1,
                'signature': "mining_reward"
            })
            
            block = {
                'index': len(self.chain),
                'timestamp': time.time(),
                'transactions': confirmed_transactions,
                'proof': proof,
                'previous_hash': previous_hash or self.hash(self.chain[-1]),
            }

            block['hash'] = self.hash(block)
            self.chain.append(block)
            
            # 重新计算余额
            self.recalculate_balances()
            
            # 广播新区块
            threading.Thread(target=self.broadcast_new_block, args=(block,)).start()
            
            self.last_update_time = time.time()
            return block

    def new_transaction(self, sender, recipient, amount):
        """创建新交易"""
        with self.lock:
            if amount <= 0:
                return -1, "金额必须大于0"
                
            # 检查可用余额
            if self.wallets.get(sender, {}).get('available', 0) < amount:
                return -1, "可用余额不足"
            
            # 创建交易ID
            txid = f"tx-{int(time.time() * 1000)}-{sender[:4]}-{recipient[:4]}"
            
            transaction = {
                'txid': txid,
                'sender': sender,
                'recipient': recipient,
                'amount': amount,
                'timestamp': time.time(),
                'status': 'pending',
                'data': {
                    'sender': sender,
                    'recipient': recipient,
                    'amount': amount,
                    'signature': f"signed-by-{sender}"
                }
            }
            
            self.pending_transactions[txid] = transaction
            
            # 重新计算余额（锁定资金）
            self.recalculate_balances()
            
            # 广播新交易
            threading.Thread(target=self.broadcast_new_transaction, args=(transaction,)).start()
            
            return txid, "交易已创建，等待确认"

    def confirm_transaction(self, txid, action):
        """确认或取消交易"""
        with self.lock:
            if txid not in self.pending_transactions:
                return False, "交易不存在"
                
            tx = self.pending_transactions[txid]
            
            if action == 'confirm':
                # 检查可用余额
                if self.wallets.get(tx['sender'], {}).get('available', 0) < tx['amount']:
                    return False, "发送方可用余额不足"
                    
                tx['status'] = 'confirmed'
                self.pending_transactions[txid] = tx
                self.recalculate_balances()
                # 广播交易状态更新
                threading.Thread(target=self.broadcast_transaction_update, args=(tx,)).start()
                return True, "交易已确认"
                
            elif action == 'cancel':
                tx['status'] = 'canceled'
                self.pending_transactions[txid] = tx
                # 广播交易状态更新
                threading.Thread(target=self.broadcast_transaction_update, args=(tx,)).start()
                # 30秒后删除
                threading.Timer(30, self.remove_canceled_transaction, args=[txid]).start()
                self.recalculate_balances()
                return True, "交易已取消"
                
            return False, "无效操作"

    def remove_canceled_transaction(self, txid):
        """删除已取消的交易"""
        with self.lock:
            if txid in self.pending_transactions and self.pending_transactions[txid]['status'] == 'canceled':
                del self.pending_transactions[txid]
                self.recalculate_balances()

    @staticmethod
    def hash(block):
        """创建区块的SHA-256哈希"""
        block_copy = block.copy()
        block_copy.setdefault('index', 0)
        block_copy.setdefault('timestamp', 0)
        block_copy.setdefault('transactions', [])
        block_copy.setdefault('proof', 0)
        block_copy.setdefault('previous_hash', '0')
        
        if 'hash' in block_copy:
            del block_copy['hash']
            
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        """工作量证明算法（低难度）"""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """验证工作量证明（低难度）"""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:2] == "00"

    def broadcast_new_block(self, block):
        """广播新区块"""
        if not self.nodes:
            return
            
        for node in self.nodes:
            try:
                url = f"http://{node}/blocks/new"
                self.send_request(
                    url,
                    method='POST',
                    data=json.dumps(block),
                    headers={'Content-Type': 'application/json'},
                    timeout=1
                )
            except:
                pass

    def broadcast_new_transaction(self, transaction):
        """广播新交易"""
        if not self.nodes:
            return
            
        for node in self.nodes:
            try:
                url = f"http://{node}/transactions/pending"
                self.send_request(
                    url,
                    method='POST',
                    data=json.dumps(transaction),
                    headers={'Content-Type': 'application/json'},
                    timeout=1
                )
            except:
                pass
                
    def broadcast_transaction_update(self, transaction):
        """广播交易状态更新"""
        if not self.nodes:
            return
            
        for node in self.nodes:
            try:
                url = f"http://{node}/transactions/update"
                self.send_request(
                    url,
                    method='POST',
                    data=json.dumps(transaction),
                    headers={'Content-Type': 'application/json'},
                    timeout=1
                )
            except:
                pass

    @staticmethod
    def send_request(url, method='GET', data=None, headers=None, timeout=5):
        """发送HTTP请求"""
        import urllib.request
        import urllib.error
        
        if headers is None:
            headers = {}
            
        req = urllib.request.Request(
            url, 
            data=data.encode() if data else None, 
            headers=headers, 
            method=method
        )
        
        try:
            response = urllib.request.urlopen(req, timeout=timeout)
            return {
                'status_code': response.getcode(),
                'json': json.loads(response.read().decode())
            }
        except urllib.error.HTTPError as e:
            return {'status_code': e.code}
        except:
            return {'status_code': 500}

class NodeDiscover:
    """节点自动发现服务"""
    def __init__(self, blockchain, port=5000):
        self.blockchain = blockchain
        self.port = port
        self.running = False
        self.thread = None
        self.broadcast_thread = None

    def start(self):
        """启动节点发现服务"""
        self.running = True
        self.broadcast_thread = threading.Thread(target=self._broadcast_existence)
        self.broadcast_thread.daemon = True
        self.broadcast_thread.start()
        
        self.thread = threading.Thread(target=self._discovery_service)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        """停止节点发现服务"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        if self.broadcast_thread:
            self.broadcast_thread.join(timeout=1)

    def _broadcast_existence(self):
        """定期广播自身存在"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                host_ip = socket.gethostbyname(socket.gethostname())
                message = f"BLOCKCHAIN_NODE:{host_ip}:{self.port}"
                sock.sendto(message.encode(), ('255.255.255.255', 8888))
                time.sleep(10)
            except:
                time.sleep(10)

    def _discovery_service(self):
        """节点发现服务主循环"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 8888))
        sock.settimeout(1)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                data_str = data.decode()
                
                if data_str.startswith("BLOCKCHAIN_NODE:"):
                    parts = data_str.split(':')
                    if len(parts) >= 3:
                        ip = parts[1]
                        port = parts[2]
                        node_address = f"{ip}:{port}"
                        
                        if node_address != f"127.0.0.1:{self.port}" and node_address != f"{addr[0]}:{self.port}":
                            self.blockchain.register_node(node_address)
                
                elif data_str == 'BLOCKCHAIN_DISCOVERY':
                    host_ip = socket.gethostbyname(socket.gethostname())
                    response = f"BLOCKCHAIN_NODE:{host_ip}:{self.port}"
                    sock.sendto(response.encode(), addr)
            except socket.timeout:
                pass
            except:
                pass

# 创建Flask应用
app = Flask(__name__)
blockchain = None
node_discover = None
app.config['PORT'] = 5000

@app.route('/')
def index():
    if blockchain is None:
        return "系统初始化中...", 500
        
    wallet = blockchain.wallets.get(blockchain.node_id, {
        'total': 100,
        'locked': 0,
        'available': 100
    })
    
    return render_template('index.html', 
                           node_id=blockchain.node_id,
                           node_name=blockchain.node_name,
                           total_balance=wallet['total'],
                           locked_balance=wallet['locked'],
                           available_balance=wallet['available'])

@app.route('/chain')
def full_chain():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'last_update': blockchain.last_update_time
    })

@app.route('/nodes')
def get_nodes():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    return jsonify({
        'nodes': list(blockchain.nodes),
        'node_names': blockchain.node_names
    })

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    values = request.get_json()
    if not values:
        return '无效请求', 400
        
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return '参数缺失', 400

    txid, message = blockchain.new_transaction(
        values['sender'],
        values['recipient'],
        values['amount']
    )
    
    if txid == -1:
        return jsonify({'message': message}), 400
    
    return jsonify({'txid': txid, 'message': message}), 201

@app.route('/transaction/confirm', methods=['POST'])
def confirm_transaction():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    values = request.get_json()
    if not values:
        return '无效请求', 400
        
    required = ['txid', 'action']
    if not all(k in values for k in required):
        return '参数缺失', 400

    success, message = blockchain.confirm_transaction(values['txid'], values['action'])
    
    if not success:
        return jsonify({'message': message}), 400
    
    return jsonify({'message': message}), 200

@app.route('/node/name', methods=['POST'])
def update_node_name():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    values = request.get_json()
    if not values:
        return '无效请求', 400
        
    required = ['node_id', 'new_name']
    if not all(k in values for k in required):
        return '参数缺失', 400

    success, message = blockchain.update_node_name(values['node_id'], values['new_name'])
    
    if success:
        # 如果是更新本节点名称
        if values['node_id'] == blockchain.node_id:
            blockchain.node_name = values['new_name']
        return jsonify({'message': message}), 200
    else:
        return jsonify({'message': message}), 400

@app.route('/mine')
def mine():
    if blockchain is None or not blockchain.last_block:
        return jsonify({"error": "系统初始化中"}), 500
        
    if blockchain.mining_lock.locked():
        return jsonify({"error": "挖矿进行中"}), 400
        
    with blockchain.mining_lock:
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block['proof'])
        block = blockchain.new_block(proof)

        return jsonify({
            'message': "新区块已创建",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'hash': block['hash']
        }), 200

@app.route('/nodes/resolve')
def consensus():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': '区块链已更新',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': '当前已是最新区块链',
            'chain': blockchain.chain
        }
    return jsonify(response), 200

@app.route('/blocks/new', methods=['POST'])
def receive_block():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    block = request.get_json()
    if not block:
        return "无效请求", 400
    
    last_block = blockchain.last_block
    if last_block is None:
        return "无区块", 400
        
    if block['index'] <= last_block['index']:
        return "区块高度过低", 400
    
    if block['previous_hash'] != blockchain.hash(last_block):
        return "哈希不匹配", 400
    
    if not blockchain.valid_proof(last_block['proof'], block['proof']):
        return "无效工作量证明", 400
    
    blockchain.chain.append(block)
    blockchain.recalculate_balances()
    blockchain.last_update_time = time.time()
    return "区块已添加", 201

@app.route('/transactions/pending', methods=['POST'])
def receive_pending_transaction():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    transaction = request.get_json()
    if not transaction:
        return "无效请求", 400
    
    txid = transaction.get('txid')
    if txid and txid not in blockchain.pending_transactions:
        blockchain.pending_transactions[txid] = transaction
        blockchain.recalculate_balances()
        return "交易已添加", 201
    return "交易已存在", 200

@app.route('/transactions/update', methods=['POST'])
def receive_transaction_update():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    transaction = request.get_json()
    if not transaction:
        return "无效请求", 400
    
    txid = transaction.get('txid')
    if txid and txid in blockchain.pending_transactions:
        blockchain.pending_transactions[txid] = transaction
        blockchain.recalculate_balances()
        return "交易已更新", 200
    return "交易不存在", 404

@app.route('/transactions/pending')
def get_pending_transactions():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    relevant_txs = []
    for txid, tx in blockchain.pending_transactions.items():
        if tx['status'] == 'pending' and (tx['recipient'] == blockchain.node_id or tx['sender'] == blockchain.node_id):
            relevant_txs.append(tx)
    
    return jsonify({'pending_transactions': relevant_txs})

@app.route('/wallet')
def get_wallet():
    if blockchain is None:
        return jsonify({"error": "系统初始化中"}), 500
        
    wallet = blockchain.wallets.get(blockchain.node_id, {
        'total': 100,
        'locked': 0,
        'available': 100
    })
    
    return jsonify({
        'address': blockchain.node_id,
        'node_name': blockchain.node_name,
        'total': wallet['total'],
        'locked': wallet['locked'],
        'available': wallet['available'],
        'nodes': list(blockchain.nodes),
        'node_names': blockchain.node_names,
        'last_update': blockchain.last_update_time
    })

def start_discovery(port):
    global node_discover
    node_discover = NodeDiscover(blockchain, port)
    node_discover.start()

def run_app(port=5000):
    global blockchain
    app.config['PORT'] = port
    blockchain = Blockchain(port)
    start_discovery(port)
    app.run(host='0.0.0.0', port=port, threaded=True)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='教学区块链节点')
    parser.add_argument('-p', '--port', type=int, default=5000, help='端口号')
    args = parser.parse_args()
    run_app(port=args.port)