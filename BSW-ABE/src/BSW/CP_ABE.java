package BSW;

import EHCP_ABE.Node;
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
import java.util.stream.Collectors;

public class CP_ABE {
    public static Element r__;

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        mskProp.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
        mskProp.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));

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
        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("alpha"))).getImmutable();
        Element beta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("beta"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element D = g.powZn((alpha.add(r)).div(beta)).getImmutable();

        for (int attribute : userAttList){
            Element r_j = bp.getZr().newRandomElement().getImmutable();
            Element D_j = g.powZn(r).mul(hash(Integer.toString(attribute), bp).powZn(r_j)).getImmutable();
            Element D_j_pie = g.powZn(r_j).getImmutable();

            skProp.setProperty("Dpie" + attribute, Base64.getEncoder().withoutPadding().encodeToString(D_j_pie.toBytes()));
            skProp.setProperty("D" + attribute, Base64.getEncoder().withoutPadding().encodeToString(D_j.toBytes()));
        }

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        skProp.setProperty("attributes", Arrays.toString(userAttList));

        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element message, Node[] accessTree,
                               String pkFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);

        Element egg_a = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("egg_alpha"))).getImmutable();
        Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("h"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();

        Node root = accessTree[0];
        //根节点的秘密数
        Element s = bp.getZr().newRandomElement().getImmutable();
        root.secretShare = s;

        Properties ctProp = new Properties();
        //1.设置密文第一部分
        Element C_ware = (message.mul(egg_a.powZn(s).getImmutable())).getImmutable();
        ctProp.setProperty("C_ware", Base64.getEncoder().withoutPadding().encodeToString(C_ware.toBytes()));

        //2.设置密文第二部分
        Element c = h.powZn(s).getImmutable();
        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(c.toBytes()));

        //3.递归设置子节点
        compute(accessTree, root, g, ctProp, pairingParametersFileName);

        storePropToFile(ctProp, ctFileName);
    }

    public static Element Decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName,
                                  int[] indexs) { // 增加需要解密的非叶子结点的索引集合
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties skProp = loadPropFromFile(skFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        String userAttListString = skProp.getProperty("attributes");
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length() - 1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        Element decryptNode = decryptNode(skProp, ctProp, accessTree, accessTree[0], userAttList, bp);
        if (decryptNode != null) {
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D"))).getImmutable();
            Element C = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C"))).getImmutable();
            Element c_wave = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C_ware"))).getImmutable();
            return c_wave.div(bp.pairing(C, D).div(decryptNode));
        }
        return null;
    }

    private static void compute(Node[] accessTree, Node node, Element g, Properties ctProp, String pairingParametersFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element secretNumber = node.secretShare;
        if (!node.isLeaf()) {
            //节点选择的多项式
            Element[] coef = randomP(node.gate[0], secretNumber, bp);
            for (int child : node.children) {
                Node childNode = accessTree[child];
                childNode.secretShare = qx(bp.getZr().newElement(child), coef, bp);
                //递归去设置子节点
                compute(accessTree, childNode, g, ctProp, pairingParametersFileName);
            }
        }

        //节点是叶节点
        if (node.isLeaf()) {
            //属性
            int attribute = node.att;

            Element c_y = (g.powZn(node.secretShare)).getImmutable();
            Element c_y_pie = (hash(
                    Integer.toString(attribute), bp
            ).powZn(node.secretShare)).getImmutable();
            ctProp.setProperty("C" + attribute, Base64.getEncoder().withoutPadding().encodeToString(c_y.toBytes()));
            ctProp.setProperty("Cpie" + attribute, Base64.getEncoder().withoutPadding().encodeToString(c_y_pie.toBytes()));
        }
        System.out.println(node + "\n" + bp.pairing(g, g).powZn(secretNumber.mul(r__))); // e(g, g)^rq;
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
                return bp.pairing(dj, cy).div(bp.pairing(djPie, cyPie)).getImmutable();
            } else {
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
            return result.getImmutable();
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
//        Element[] message = new Element[arraySize];

        // 初始化第0个元素为GT中的随机元素
        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
//        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + message);
        encrypt(pairingParametersFileName, message, accessTree, pkFileName, ctFileName);

        int[] indexs = {0};
        Element res = Decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName, indexs);
        System.out.println("解密结果:" + res);
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }
}
