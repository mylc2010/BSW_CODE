package CR_FH_CPABE;

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
//    public static Element R__ = null;
//    public static Element omega__ = null;
//    public static Element[] R = new Element[100];

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName, int n) { // 等级的最大值
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta1 = bp.getZr().newRandomElement().getImmutable();
        Element beta2 = bp.getZr().newRandomElement().getImmutable();
        Element beta3 = bp.getZr().newRandomElement().getImmutable();
        Element theta = bp.getZr().newRandomElement().getImmutable();
//        beta__ = beta;

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();
        Element f1 = g.powZn(beta1).getImmutable();
        Element f2 = g.powZn(beta2).getImmutable();
        Element f3 = g.powZn(beta3).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        mskProp.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        mskProp.setProperty("beta1", Base64.getEncoder().withoutPadding().encodeToString(beta1.toBytes()));
        mskProp.setProperty("beta2", Base64.getEncoder().withoutPadding().encodeToString(beta2.toBytes()));
        mskProp.setProperty("beta3", Base64.getEncoder().withoutPadding().encodeToString(beta3.toBytes()));
        mskProp.setProperty("theta", Base64.getEncoder().withoutPadding().encodeToString(theta.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));
        pkProp.setProperty("f1", Base64.getEncoder().withoutPadding().encodeToString(f1.toBytes()));
        pkProp.setProperty("f2", Base64.getEncoder().withoutPadding().encodeToString(f2.toBytes()));
        pkProp.setProperty("f3", Base64.getEncoder().withoutPadding().encodeToString(f3.toBytes()));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException { // 输入用户的等级, 计算用户的私钥.
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = new Properties();
        Properties mskProp = loadPropFromFile(mskFileName);
        Properties pkProp = loadPropFromFile(pkFileName);

        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("alpha"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element beta1 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("beta1"))).getImmutable();
        Element beta2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("beta2"))).getImmutable();
        Element beta3 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("beta3"))).getImmutable();
        Element theta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("theta"))).getImmutable();

        Element r = bp.getZr().newRandomElement().getImmutable();
        Element omega = hashZp(getUID(), bp).getImmutable();

//        R__ = r;
//        omega__ = omega;

        Element D = g.powZn((alpha.add(theta)).div(beta1)).getImmutable();
        Element E = g.powZn((theta.add(r).add(omega)).div(beta2)).getImmutable();
        Element Epie = g.powZn((r.add(omega)).div(beta3)).getImmutable();

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        skProp.setProperty("E", Base64.getEncoder().withoutPadding().encodeToString(E.toBytes()));
        skProp.setProperty("Epie", Base64.getEncoder().withoutPadding().encodeToString(Epie.toBytes()));

        for (int att : userAttList) {
            Element ri = bp.getZr().newRandomElement().getImmutable();

            Element Di = (g.powZn(r.add(omega))).mul(hash(Integer.toString(att), bp).powZn(ri)).getImmutable();
            Element DiPie = g.powZn(ri).getImmutable();

            skProp.setProperty("D" + att, Base64.getEncoder().withoutPadding().encodeToString(Di.toBytes()));
            skProp.setProperty("Dpie" + att, Base64.getEncoder().withoutPadding().encodeToString(DiPie.toBytes()));
        }

        skProp.setProperty("attributes", Arrays.toString(userAttList));

        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element[] message, Node[] accessTree,
                               String pkFileName, String ctFileName, String mskFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        Properties mskProp = loadPropFromFile(mskFileName);

        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("egg_alpha"))).getImmutable();
        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("alpha"))).getImmutable();
        Element f1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("f1"))).getImmutable();
        Element f2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("f2"))).getImmutable();
        Element f3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("f3"))).getImmutable();

        Node root = accessTree[0];
        //根节点的秘密数
        Element s = bp.getZr().newRandomElement().getImmutable();
        root.secretShare = s;

        Properties ctProp = new Properties();

        compute(accessTree, root, g, ctProp, pairingParametersFileName);

        Element[] epsilons = new Element[accessTree.length];
        for (Node node :accessTree) {
            if (!node.isLeaf()) {
                int index = node.index;
                epsilons[index] = bp.getZr().newRandomElement().getImmutable();
            }
        }
        for (Node node : accessTree) {
            if (!node.isLeaf()) {
                int index = node.index;
                Element epsilon = epsilons[index];
                if (node.isTran) {
                    Element vx = hashGT(bp.pairing(g.powZn(alpha), g.powZn(node.secretShare.add(epsilon))), bp).getImmutable();
                    for (int i = 0; i < node.children.length; i++) {
                        Element l = bp.getZr().newRandomElement().getImmutable();
                        Node child = accessTree[node.children[i]];
                        if (child.isLeaf()) continue;
                        Element cTran = bp.pairing(g.powZn(vx), g.powZn(l)).mul(
                                bp.pairing(g.powZn(alpha), g.powZn(child.secretShare.add(epsilons[child.index])))
                        ).getImmutable();
                        Element cTranPie = g.powZn(l).getImmutable();

                        ctProp.setProperty("cTran" + child.index, Base64.getEncoder().withoutPadding().encodeToString(cTran.toBytes()));
                        ctProp.setProperty("cTranPie" + child.index, Base64.getEncoder().withoutPadding().encodeToString(cTranPie.toBytes()));
                    }
                }

                if (message[index] != null) {
                    Element C1 = message[index].mul(bp.pairing(g.powZn(alpha), g.powZn(node.secretShare.add(epsilon)))).getImmutable();
                    Element C2 = f1.powZn(node.secretShare.add(epsilon)).getImmutable();
                    Element C3 = f2.powZn(node.secretShare.add(epsilon)).getImmutable();
                    Element C4 = f3.powZn(epsilon).getImmutable();

                    ctProp.setProperty("C1_" + index, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                    ctProp.setProperty("C2_" + index, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
                    ctProp.setProperty("C3_" + index, Base64.getEncoder().withoutPadding().encodeToString(C3.toBytes()));
                    ctProp.setProperty("C4_" + index, Base64.getEncoder().withoutPadding().encodeToString(C4.toBytes()));
                }
            }
        }

        storePropToFile(ctProp, ctFileName);
//        // 计算秘密值, 调试是否成功解密秘密值;
//        System.out.println("Encryption");
//        System.out.println("3" + bp.pairing(g.powZn(R__.add(omega__)), g.powZn(accessTree[3].secretShare)));
//        System.out.println("5" + bp.pairing(g, g).powZn((R__.add(omega__)).mul(accessTree[5].secretShare)));
//        System.out.println("4" + bp.pairing(g.powZn(R__.add(omega__)), g.powZn(accessTree[4].secretShare)));
    }

    public static Element[] Decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName,
                                  String pkFileName, int[] indexs) { // 增加需要解密的非叶子结点的索引集合
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties skProp = loadPropFromFile(skFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        Properties pkProp = loadPropFromFile(pkFileName);

        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D"))).getImmutable();
        Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("E"))).getImmutable();
        Element Epie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("Epie"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        String userAttListString = skProp.getProperty("attributes");
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length() - 1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        decryptNode(skProp, ctProp, accessTree, accessTree[0], userAttList, bp);

//        System.out.println("Decrypt");
//        System.out.println("5" + accessTree[5].secretShare);
//        for (BSW.Node node :accessTree) {
//            if (!node.isLeaf()) {
//                System.out.println(node + "\n" + node.secretShare);
//            }
//        }

        ArrayList<Element> messages = new ArrayList<>();
        Element[] F = new Element[accessTree.length];

        // 进行秘密恢复
        for (int index : indexs) {  // 从上往下便于解密, 可以根据父节点的恢复结果进行恢复
            if (accessTree[index].valid) {
                Node node = accessTree[index];
                Element Fpie;
                Element C1x = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C1_" + node.index))).getImmutable();

                if (node.father != -1 && accessTree[node.father].valid && F[node.father] != null) { // 可以通过父节点的Fpie转移到当前节点
                    Node fa = accessTree[node.father];
                    Element cTran = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("cTran" + node.index))).getImmutable();
                    Element cTranPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("cTranPie" + node.index))).getImmutable();

                    Fpie = cTran.div(bp.pairing(cTranPie, g).powZn(hashGT(F[fa.index], bp))).getImmutable();
                } else {
                    Element C2x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C2_" + node.index))).getImmutable();
                    Element C3x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C3_" + node.index))).getImmutable();
                    Element C4x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C4_" + node.index))).getImmutable();

                    Fpie = bp.pairing(C2x, D).mul(bp.pairing(C4x, Epie)).mul(node.secretShare)
                            .div(bp.pairing(C3x, E)).getImmutable();
                }

                F[index] = Fpie.getImmutable();
                Element message = C1x.div(Fpie).getImmutable();

                messages.add(message);
            }
            else {
                System.out.println("You can't decrypt the node " + index + "!!!");
            }
        }
        return messages.toArray(new Element[0]);
    }

    private static void compute(Node[] accessTree, Node node, Element g, Properties ctProp, String pairingParametersFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element secretNumber = node.secretShare.getImmutable();
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
//        System.out.println(node + "\n" + bp.pairing(g, g).powZn(secretNumber.mul(r__))); // e(g, g)^rq;
    }

    public static Element decryptNode(Properties skProp, Properties ctProp, Node[] accessTree, Node node, int[] attributes, Pairing bp) {
        //叶子节点
        if (node.isLeaf()) {
            int attribute = node.att;
            if (Arrays.stream(attributes).boxed().collect(Collectors.toList()).contains(attribute)) {
                Element cy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C" + attribute))).getImmutable();
                Element cyPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("Cpie" + attribute))).getImmutable();
                Element dj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D" + attribute))).getImmutable();
                Element djPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("Dpie" + attribute))).getImmutable();

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

    public static String getUID() { // TODO 为每个用户赋予一个唯一ID, 是否传参?
        return UUID.randomUUID().toString();
    }

    public static Element hash(String att, Pairing bp) throws NoSuchAlgorithmException {
        // 使用 SHA-256 计算哈希
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(att.getBytes(StandardCharsets.UTF_8));
        // 将哈希结果映射到 G1 群元素
        return bp.getG1().newElement().setFromHash(hashBytes, 0, hashBytes.length).getImmutable();
    }

    public static Element hashZp(String uid, Pairing bp) throws NoSuchAlgorithmException {
        // 使用 SHA-256 计算哈希
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(uid.getBytes(StandardCharsets.UTF_8));
        // 将哈希结果映射到 ZP 群元素
        return bp.getZr().newElement().setFromHash(hashBytes, 0, hashBytes.length).getImmutable();
    }

    public static Element hashGT(Element element, Pairing bp) { // TODO 将GT中的元素映射到Zr上.
        return bp.getZr().newElementFromHash(element.toBytes(), 0, element.toBytes().length).getImmutable();
    }

    public static int[][] StringTo2DArray(String input) {
        input = input.substring(1, input.length() - 1);

        // 分割子数组
        String[] subArrays = input.split("\\], \\[");

        // 去除多余字符并转换为二维数组
        List<int[]> list = new ArrayList<>();
        for (String subArray : subArrays) {
            subArray = subArray.replace("[", "").replace("]", "");
            String[] numbers = subArray.split(", ");
            int[] intArray = new int[numbers.length];
            for (int i = 0; i < numbers.length; i++) {
                intArray[i] = Integer.parseInt(numbers[i]);
            }
            list.add(intArray);
        }

        return list.toArray(new int[0][]);
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
        int[] userAttList = {2, 6, 7, 8, 9, 10};

        Node[] accessTree = new Node[11];
        accessTree[0] = new Node(new int[]{2, 2}, new int[]{1, 2}, true, 0, -1); // -1 表示根节点
        accessTree[1] = new Node(new int[]{3, 3}, new int[]{3, 4, 5}, true, 1, 0);
        accessTree[2] = new Node(2);
        accessTree[3] = new Node(new int[]{2, 2}, new int[]{6, 7}, false, 3, 1);
        accessTree[4] = new Node(new int[]{2, 2}, new int[]{9, 10}, false, 4, 1);
        accessTree[5] = new Node(new int[]{1, 1}, new int[]{8}, false, 5, 1);
        accessTree[6] = new Node(6);
        accessTree[7] = new Node(7);
        accessTree[8] = new Node(8);
        accessTree[9] = new Node(9);
        accessTree[10] = new Node(10);

        String dir = "BSW-ABE/data/";
        String pairingParametersFileName = "BSW-ABE/a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName, 4);
        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

        int arraySize = 13; // 设置所需大小

        // 创建Element数组
        Element[] message = new Element[arraySize];

        // 初始化第0个元素为GT中的随机元素
        message[0] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[1] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[3] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[4] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[5] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();

//        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + Arrays.toString(message));
        encrypt(pairingParametersFileName, message, accessTree, pkFileName, ctFileName, mskFileName);

        int[] indexs = {0, 1, 3, 4, 5};
        Element[] res = Decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName, pkFileName, indexs);
        System.out.println("解密结果:" + Arrays.toString(res));
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }
}
