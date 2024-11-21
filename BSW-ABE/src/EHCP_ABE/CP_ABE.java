package EHCP_ABE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.DoubleToIntFunction;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class CP_ABE {
    public static Element r__;
    public static Element beta__;

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) { // 等级的最大值
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element phi = bp.getZr().newRandomElement().getImmutable();
//        beta__ = beta;

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        mskProp.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
        mskProp.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        mskProp.setProperty("phi", Base64.getEncoder().withoutPadding().encodeToString(phi.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("g_beta", Base64.getEncoder().withoutPadding().encodeToString(g_beta.toBytes()));
        pkProp.setProperty("h", Base64.getEncoder().withoutPadding().encodeToString(g_beta.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));
        // H2在util中实现
        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = new Properties();
        Properties mskProp = loadPropFromFile(mskFileName);
        Properties pkProp = loadPropFromFile(pkFileName);

        Element r = bp.getZr().newRandomElement().getImmutable();
        r__ = r;
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("g_alpha"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("h"))).getImmutable();
        Element D = g_alpha.mul(h.powZn(r)).getImmutable();

        for (int attribute : userAttList){
            Element r_j = bp.getZr().newRandomElement().getImmutable();
            Element D_j = g.powZn(r).mul(hash(Integer.toString(attribute), bp).powZn(r_j)).getImmutable();
            Element D_j_pie = h.powZn(r_j).getImmutable();

            skProp.setProperty("Dpie" + attribute, Base64.getEncoder().withoutPadding().encodeToString(D_j_pie.toBytes()));
            skProp.setProperty("D" + attribute, Base64.getEncoder().withoutPadding().encodeToString(D_j.toBytes()));
        }

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        skProp.setProperty("attributes", Arrays.toString(userAttList));

        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element[] message, Node[] accessTree,
                               String pkFileName, String ctFileName, String mskFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        Properties mskProp = loadPropFromFile(mskFileName);

        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("egg_alpha"))).getImmutable();
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("g_alpha"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("h"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();

        Node root = accessTree[0];
        //根节点的秘密数
        Element s = bp.getZr().newRandomElement().getImmutable();
        root.secretShare = s;

        Properties ctProp = new Properties();

        compute(accessTree, root, h, ctProp, pairingParametersFileName);

        for (Node node : accessTree) {
            if (!node.isLeaf()) {
                Element rho = node.secretShare.getImmutable();
                Element Rx = bp.getGT().newRandomElement().getImmutable();
                Element C1x = Rx.mul(bp.pairing(g_alpha, g.powZn(rho))).getImmutable();
                Element C2x = g.powZn(rho);
                String key = C1x.toString() + C2x.toString() + Rx;
                String C3x = util.encryptABE(message[node.index], key); // 每个非叶子结点都有一个对应的消息, 应该传递数组.

                System.out.println("key:" + key);
                System.out.println("C3x:" + C3x);

                ctProp.setProperty("C1x-" + node.index, Base64.getEncoder().withoutPadding().encodeToString(C1x.toBytes()));
                ctProp.setProperty("C2x-" + node.index, Base64.getEncoder().withoutPadding().encodeToString(C2x.toBytes()));
                assert C3x != null;
                ctProp.setProperty("C3x-" + node.index, Base64.getEncoder().withoutPadding().encodeToString(C3x.getBytes(StandardCharsets.UTF_8)));
            }
//            System.out.println(node + "\n" + bp.pairing(g, g).powZn(node.secretShare.mul(r__).mul(beta__))); // e(g, g)^rbq;
        }

        storePropToFile(ctProp, ctFileName);
    }

    public static Element[] Decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName,
                                  int[] indexs) { // 增加需要解密的非叶子结点的索引集合
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties skProp = loadPropFromFile(skFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D"))).getImmutable();
        String userAttListString = skProp.getProperty("attributes");
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length() - 1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        decryptNode(skProp, ctProp, accessTree, accessTree[0], userAttList, bp);

        ArrayList<Element> messages = new ArrayList<>();
        // 进行秘密恢复
        for (int index : indexs) {
            if (accessTree[index].valid) {
                Node node = accessTree[index];
                String C1xtring = ctProp.getProperty("C1x-" + node.index);
                Element C1x = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(C1xtring)).getImmutable();
                String C2xtring = ctProp.getProperty("C2x-" + node.index);
                Element C2x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2xtring)).getImmutable();
                String C3xtring = ctProp.getProperty("C3x-" + node.index);
                String C3x = new String(Base64.getDecoder().decode(C3xtring), StandardCharsets.UTF_8);

                Element Rx = C1x.div(bp.pairing(C2x, D).div(node.secretShare)).getImmutable();
                String key = C1x + C2x.toString() + Rx;
                System.out.println("key:" + key);
                System.out.println("C3x:" + C3x);
                messages.add(util.decryptABE(C3x, key, bp));
            }
            else {
                System.out.println("You can't decrypt the node " + index + "!!!");
            }
        }
        return messages.toArray(new Element[0]);
    }

    private static void compute(Node[] accessTree, Node node, Element h, Properties ctProp, String pairingParametersFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element secretNumber = node.secretShare;
        if (!node.isLeaf()) {
            //节点选择的多项式
            Element[] coef = randomP(node.gate[0], secretNumber, bp);
            for (int child : node.children) {
                Node childNode = accessTree[child];
                childNode.secretShare = qx(bp.getZr().newElement(child), coef, bp);
                //递归去设置子节点
                compute(accessTree, childNode, h, ctProp, pairingParametersFileName);
            }
            node.coef = coef;
        }

        //节点是叶节点
        if (node.isLeaf()) {
            //属性
            int attribute = node.att;

            Element c_y = (h.powZn(node.secretShare)).getImmutable();
            Element c_y_pie = (hash(
                    Integer.toString(attribute), bp
            ).powZn(node.secretShare)).getImmutable();
            ctProp.setProperty("C" + attribute, Base64.getEncoder().withoutPadding().encodeToString(c_y.toBytes()));
            ctProp.setProperty("Cpie" + attribute, Base64.getEncoder().withoutPadding().encodeToString(c_y_pie.toBytes()));
        }
    }

    public static Element decryptNode(Properties skProp, Properties ctProp, Node[] accessTree, Node node, int[] attributes, Pairing bp) {
        //叶子节点
        if (node.isLeaf()) {
            int attribute = node.att;
            if (Arrays.stream(attributes).boxed().collect(Collectors.toList()).contains(attribute)) {
                Element cy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C" + attribute))).getImmutable();
                Element cyPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("Cpie" + attribute))).getImmutable();
                Element dj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D" + attribute)));
                Element djPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("Dpie" + attribute)));

                node.secretShare = bp.pairing(dj, cy).div(bp.pairing(djPie, cyPie)).getImmutable();
                node.valid = true;
//                System.out.println(node + "\n" + node.secretShare);

                return node.secretShare;
            } else {
                node.valid = false;
                return null;
            }
        } else {
            //内部节点
            int threshold = node.gate[0];
            int satisfyCount = 0;

            //重建
            Map<Element, Element> indexFzMap = new HashMap<>();
            for (int child : node.children) {
                Element decryptNode = decryptNode(skProp, ctProp, accessTree, accessTree[child], attributes, bp);
                if (decryptNode != null) {
                    satisfyCount++;
                    Element index = bp.getZr().newElement(child).getImmutable();
                    indexFzMap.put(index, decryptNode);
                }
            }
//            System.out.println("satisfyCount:" + node + " " + satisfyCount);
            if (satisfyCount < threshold) {
                node.valid = false;
                return null;
            }

            Element result = bp.getGT().newOneElement();
            Element zero = bp.getZr().newZeroElement().getImmutable();
            List<Element> Sx = new ArrayList<>(indexFzMap.keySet());
            for (Map.Entry<Element, Element> entry : indexFzMap.entrySet()) {
                Element curIndex = entry.getKey();
                Element curFz = entry.getValue();
                Element powZn = lagrange(curIndex, Sx, zero, bp.getZr());
                result.mul((curFz.powZn(powZn)));
            }

            node.valid = true;
            node.secretShare = result.getImmutable();
//            System.out.println(node + "\n" + node.secretShare);

            return node.secretShare;
        }
    }

    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    public static Element qx(Element index, Element[] coef, Pairing bp) {
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            //index一定要使用duplicate复制使用，因为index在每一次循环中都要使用，如果不加duplicte，index的值会发生变化
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    public static Element lagrange(Element i, List<Element> s, Element x, Field zr){
        Element result = zr.newOneElement();
        for (Element element : s) {
            if (!i.equals(element)){
                result.mul(x.sub(element).div(i.sub(element)));
            }
        }
        return result.getImmutable();
    }

    public static Element hash(String att, Pairing bp) throws NoSuchAlgorithmException {
        // 使用 SHA-256 计算哈希
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(att.getBytes(StandardCharsets.UTF_8));
        // 将哈希结果映射到 G1 群元素
        return bp.getG1().newElement().setFromHash(hashBytes, 0, hashBytes.length).getImmutable();
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static void basicTest() throws Exception {
        int[] userAttList = {1, 2, 3, 4};

        Node[] accessTree = new Node[5];
        accessTree[0] = new Node(new int[]{4, 4}, new int[]{1, 2, 3, 4}, 0);
        accessTree[1] = new Node(1);
        accessTree[2] = new Node(2);
        accessTree[3] = new Node(3);
        accessTree[4] = new Node(4);

        String dir = "BSW-ABE/data/";
        String pairingParametersFileName = "BSW-ABE/a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName);
        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

        int arraySize = 10; // 设置所需大小

        // 创建Element数组
        Element[] message = new Element[arraySize];

        // 初始化第0个元素为GT中的随机元素
        message[0] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
//        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + Arrays.toString(message));
        encrypt(pairingParametersFileName, message, accessTree, pkFileName, ctFileName, mskFileName);

        int[] indexs = {0};
        Element[] res = Decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName, indexs);
        System.out.println("解密结果:" + Arrays.toString(res));
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }

}
