package CP_ASBE;

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
    public static Element[] R = new Element[100];
    public static Element[] Rrank = new Element[100];

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName, int n) { // 等级的最大值
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element phi = bp.getZr().newRandomElement().getImmutable();
//        beta__ = beta;

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();
        Element p = g.powZn(phi).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        mskProp.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        mskProp.setProperty("phi", Base64.getEncoder().withoutPadding().encodeToString(phi.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("p", Base64.getEncoder().withoutPadding().encodeToString(p.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));

        for (int i = 1; i <= n; i++) {
            Element beta_i = bp.getZr().newRandomElement().getImmutable();
            Element theta_i = bp.getZr().newRandomElement().getImmutable();

            Element hi = g.powZn(beta_i).getImmutable();
            Element ki = g.powZn(theta_i).getImmutable();

            mskProp.setProperty("beta" + i, Base64.getEncoder().withoutPadding().encodeToString(beta_i.toBytes()));
            mskProp.setProperty("theta" + i, Base64.getEncoder().withoutPadding().encodeToString(theta_i.toBytes()));

            pkProp.setProperty("h" + i, Base64.getEncoder().withoutPadding().encodeToString(hi.toBytes()));
            pkProp.setProperty("k" + i, Base64.getEncoder().withoutPadding().encodeToString(ki.toBytes()));
        }

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[][] userAttList, String pkFileName, String mskFileName, String skFileName
                              , int rank ) throws NoSuchAlgorithmException { // 输入用户的等级, 计算用户的私钥.
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = new Properties();
        Properties mskProp = loadPropFromFile(mskFileName);
        Properties pkProp = loadPropFromFile(pkFileName);

        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("alpha"))).getImmutable();
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element phi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("phi"))).getImmutable();

        Element rpie = bp.getZr().newRandomElement().getImmutable();
//        R[0] = rpie;

        for (int i = 1; i <= rank; i++) {
            Element ri = bp.getZr().newRandomElement().getImmutable();
            Element beta_i = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("beta" + i))).getImmutable();
            Element theta_i = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("theta" + i))).getImmutable();

            Element ki = g.powZn((alpha.add(ri)).div(beta_i)).getImmutable();
            Element ui = g.powZn((ri.add(rpie)).div(theta_i)).getImmutable();

            skProp.setProperty("k" + i, Base64.getEncoder().withoutPadding().encodeToString(ki.toBytes()));
            skProp.setProperty("u" + i, Base64.getEncoder().withoutPadding().encodeToString(ui.toBytes()));
            Rrank[i] = ri;
        }

        for (int att : userAttList[0]) {
            Element rpie_i = bp.getZr().newRandomElement().getImmutable();

            Element Di = g.powZn(rpie).mul(hash(Integer.toString(att), bp).powZn(rpie_i)).getImmutable();
            Element Di_pie = g.powZn(rpie_i).getImmutable();

            skProp.setProperty("D" + att, Base64.getEncoder().withoutPadding().encodeToString(Di.toBytes()));
            skProp.setProperty("Dpie" + att, Base64.getEncoder().withoutPadding().encodeToString(Di_pie.toBytes()));
        }
//        r__ = r;

        for (int i = 1; i < userAttList.length; i ++ ) {
            Element rpie_i = bp.getZr().newRandomElement().getImmutable();
            R[i] = rpie_i;

            for (int att : userAttList[i]) {
                Element rpie_i_k = bp.getZr().newRandomElement().getImmutable();

                Element Dii = g.powZn(rpie_i).mul(hash(Integer.toString(att), bp).powZn(rpie_i_k)).getImmutable();
                Element Dpie_i_k = g.powZn(rpie_i_k).getImmutable();

                skProp.setProperty("D" + i + att, Base64.getEncoder().withoutPadding().encodeToString(Dii.toBytes()));
                skProp.setProperty("Dpie" + i + att, Base64.getEncoder().withoutPadding().encodeToString(Dpie_i_k.toBytes()));
            }
            Element li = g.powZn((rpie.sub(rpie_i)).div(phi)).getImmutable();

            skProp.setProperty("l" + i, Base64.getEncoder().withoutPadding().encodeToString(li.toBytes()));
        }

        skProp.setProperty("attributes", Arrays.deepToString(userAttList));

        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element[] message, int[] messageRank, Node[] accessTree,
                               String pkFileName, String ctFileName, String mskFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        Properties mskProp = loadPropFromFile(mskFileName);

        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();
        Element p = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("p"))).getImmutable();
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("egg_alpha"))).getImmutable();
        Element alpha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("alpha"))).getImmutable();

        Node root = accessTree[0];
        //根节点的秘密数
        Element s = bp.getZr().newRandomElement().getImmutable();
        root.secretShare = s;

        Properties ctProp = new Properties();

        compute(accessTree, root, g, ctProp, pairingParametersFileName);

        for (Node node : accessTree) {
            if (!node.isLeaf()) {
                int index = node.index;

                node.rank = messageRank[index];

                Element hi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("h" + messageRank[index]))).getImmutable();
                Element ki = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("k" + messageRank[index]))).getImmutable();

                if (node.isTran) {
                    Element cTran_i = p.powZn(node.secretShare).getImmutable();
                    ctProp.setProperty("cTran" + index, Base64.getEncoder().withoutPadding().encodeToString(cTran_i.toBytes()));
                }

                if (message[index] == null) continue;  // 如果这个节点没有消息，则跳过

                Element C1x = message[index].mul(bp.pairing(g.powZn(alpha), g.powZn(node.secretShare))).getImmutable();
                Element C2x = p.powZn(node.secretShare).getImmutable();
                Element C3x = hi.powZn(node.secretShare).getImmutable();
                Element C4x = ki.powZn(node.secretShare).getImmutable();

                ctProp.setProperty("C1" + index, Base64.getEncoder().withoutPadding().encodeToString(C1x.toBytes()));
                ctProp.setProperty("C2" + index, Base64.getEncoder().withoutPadding().encodeToString(C2x.toBytes()));
                ctProp.setProperty("C3" + index, Base64.getEncoder().withoutPadding().encodeToString(C3x.toBytes()));
                ctProp.setProperty("C4" + index, Base64.getEncoder().withoutPadding().encodeToString(C4x.toBytes()));
            }
        }

        storePropToFile(ctProp, ctFileName);
//        // 计算秘密值, 调试是否成功解密秘密值;
//        System.out.println("Encryption");
//        System.out.println("2" + bp.pairing(g.powZn(R[1]), g.powZn(accessTree[2].secretShare)));
//        System.out.println("3" + bp.pairing(g.powZn(R[2]), g.powZn(accessTree[3].secretShare)));
//        System.out.println("1" + bp.pairing(g.powZn(R[1]), g.powZn(accessTree[1].secretShare)));
//        System.out.println("Tran");
//        System.out.println("3" + bp.pairing(g.powZn(R[1]), g.powZn(accessTree[3].secretShare)));
//        System.out.println(bp.pairing(g.powZn(Rrank[2]), g.powZn(accessTree[1].secretShare)));
    }

    public static Element[] Decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName,
                                    int[] indexs) { // 增加需要解密的非叶子结点的索引集合
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties skProp = loadPropFromFile(skFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        String userAttListString = skProp.getProperty("attributes");
        int[][] userAttList = StringTo2DArray(userAttListString);

        decryptNode(skProp, ctProp, accessTree, accessTree[0], userAttList, bp);

//        System.out.println("Decrypt");

//        for (BSW.Node node :accessTree) {
//            if (!node.isLeaf()) {
//                System.out.println(node);
//                for (int label = 0; label < userAttList.length; label++ ) {
//                    if (node.decryptNode[label] == null) continue;
//                    System.out.println(label + " " + node.decryptNode[label]);
//                }
//            }
//        }

        ArrayList<Element> messages = new ArrayList<>();
        // 进行秘密恢复
        for (int index : indexs) {
            if (accessTree[index].valid) {
                Node node = accessTree[index];
                System.out.println(node.index);

                Element C1x = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C1" + node.index))).getImmutable();
                Element C2x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C2" + node.index))).getImmutable();
                Element C3x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C3" + node.index))).getImmutable();
                Element C4x = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C4" + node.index))).getImmutable();

                Element A0x = null;
                if (node.decryptNode[0] == null) {
                    for (int label = 1; label < userAttList.length; label++) {
                        if (node.decryptNode[label] != null) {
                            Element li = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("l" + label)));
                            A0x = bp.pairing(C2x, li).mul(node.decryptNode[label]).getImmutable();
                            break;
                        }
                    }
                } else {
                    A0x = node.decryptNode[0].getImmutable();
                }

                int t = node.rank;
                Element ut = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("u" + t))).getImmutable();
                Element kt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("k" + t))).getImmutable();
                Element Atx = bp.pairing(C4x, ut).div(A0x).getImmutable();

                Element message = (C1x.mul(Atx)).div(bp.pairing(C3x, kt)).getImmutable();

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
//        System.out.println(node + "\n" + bp.pairing(g, g).powZn(secretNumber.mul(r__))); // e(g, g)^rq;
    }

    public static void decryptNode(Properties skProp, Properties ctProp, Node[] accessTree, Node node, int[][] attributes, Pairing bp) {
        node.decryptNode = new Element[attributes.length];
//        System.out.println("in" + node);

        //叶子节点
        if (node.isLeaf()) {
            int attribute = node.att;
            for (int label = 0; label < attributes.length; label ++ ) {
                if (Arrays.stream(attributes[label]).boxed().collect(Collectors.toList()).contains(attribute)) {
                    Element cy, cyPie, dj, djPie;
                    if (label == 0) {
                        cy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C" + attribute))).getImmutable();
                        cyPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("Cpie" + attribute))).getImmutable();
                        dj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D" + attribute)));
                        djPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("Dpie" + attribute)));
                    } else {
//                        System.out.println(label + " " + attribute);
                        cy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("C" + attribute))).getImmutable();
                        cyPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("Cpie" + attribute))).getImmutable();
                        dj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("D" + label + attribute)));
                        djPie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("Dpie" + label + attribute)));
                    }
                    node.decryptNode[label] = bp.pairing(dj, cy).div(bp.pairing(djPie, cyPie)).getImmutable();
                    node.valid = true;
                }
            }
        } else {
            //内部节点
            int threshold = node.gate[0];
            int countTran = 0;

            //重建
            @SuppressWarnings("unchecked") // 添加注解来忽略编译器警告
            Map<Element, Element>[] indexFzMap = (Map<Element, Element>[]) new HashMap[attributes.length];
            for (int i = 0; i < attributes.length; i++) {
                indexFzMap[i] = new HashMap<>();
            }

            List<Integer> TranList = new ArrayList<>(); // 存储有效的转移儿子节点

            for (int child : node.children) {
                decryptNode(skProp, ctProp, accessTree, accessTree[child], attributes, bp);
                boolean isValid = false;
                int cnt = 0;

                Node childNode = accessTree[child];
                for (int label = 0; label < attributes.length; label ++ ) {
                    Element decryptNode = childNode.decryptNode[label];
                    if (decryptNode != null) {
                        Element index = bp.getZr().newElement(child).getImmutable();
                        indexFzMap[label].put(index, decryptNode);
                        if (!childNode.isLeaf() && childNode.isTran) {
                            isValid = true;
                            cnt ++;
                        }
                    }
                }
                if (isValid) {
                    countTran += cnt;
                    TranList.add(child);
                }
            }

            for (int label = 0; label < attributes.length; label++) {
                Element li = null;
                if (label != 0) li = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("l" + label)));

                int satisfyCount = indexFzMap[label].size();

                if (satisfyCount >= threshold) { // 如果不需要转移节点
                    Element result = bp.getGT().newOneElement();
                    Element zero = bp.getZr().newZeroElement().getImmutable();
                    List<Element> Sx = new ArrayList<>(indexFzMap[label].keySet());
                    for (Map.Entry<Element, Element> entry : indexFzMap[label].entrySet()) {
                        Element curIndex = entry.getKey();
                        Element curFz = entry.getValue();
                        Element powZn = lagrange(curIndex, Sx, zero, bp.getZr());
                        result.mul((curFz.powZn(powZn)));
                    }

                    node.decryptNode[label] = result.getImmutable();
                }
                else {
                    int tranNeed = threshold - satisfyCount; // 需要多少个转移节点
                    Element result = bp.getGT().newOneElement();
                    Element zero = bp.getZr().newZeroElement().getImmutable();
                    for (int tran : TranList) { //TODO 需要转换才转, 不能转成相同的.
                        Node tranNode = accessTree[tran];
                        for (int lab = 1; lab < attributes.length; lab ++) { // 不能从0转成其他属性
                            if (lab == label) continue;
                            Element decryptNode = accessTree[tran].decryptNode[lab];
                            Element cTran = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProp.getProperty("cTran" + tranNode.index)));
                            Element lipie = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skProp.getProperty("l" + lab)));
                            if (decryptNode != null) {
                                Element fz;
                                Element index = bp.getZr().newElement(tranNode.index).getImmutable();
                                if (label != 0) fz = bp.pairing(cTran, lipie.div(li)).mul(tranNode.decryptNode[lab]).getImmutable(); // 检查
                                else fz = bp.pairing(cTran, lipie).mul(tranNode.decryptNode[lab]).getImmutable();
//                                System.out.println(tranNode.index + " " + label + " " + lab);
//                                System.out.println(fz);

                                indexFzMap[label].put(index, fz);
                                tranNeed--;
                            }
                        }
                        if (tranNeed <= 0) break;
                    }

//                    System.out.println(node.index + " " + label + " " + tranNeed + " " + indexFzMap[label].size());

                    if (indexFzMap[label].size() < threshold) continue; // 如果加上转化节点都不能满足要求，则退出

                    List<Element> Sx = new ArrayList<>(indexFzMap[label].keySet());
                    for (Map.Entry<Element, Element> entry : indexFzMap[label].entrySet()) {
                        Element curIndex = entry.getKey();
                        Element curFz = entry.getValue();
                        Element powZn = lagrange(curIndex, Sx, zero, bp.getZr());
                        result.mul((curFz.powZn(powZn)));
                    }

                    node.decryptNode[label] = result.getImmutable();
                }
                node.valid = true;
            }
        }
//        System.out.println("out" + node + " " + node.valid);
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
        int[][] userAttList = {{3},{8,9,10},{11,12}};

        Node[] accessTree = new Node[13];
        accessTree[0] = new Node(new int[]{2, 2}, new int[]{1,2}, false, 0);
        accessTree[1] = new Node(new int[]{1, 1}, new int[]{3}, false, 1);
        accessTree[2] = new Node(new int[]{4, 4}, new int[]{4,5,6,7}, true, 2);
        //accessTree[3] = new BSW.Node(new int[]{1, 1}, new int[]{9}, false, 3);
        accessTree[4] = new Node(new int[]{1, 1}, new int[]{8}, false, 4);
        accessTree[5] = new Node(new int[]{1, 1}, new int[]{9}, false, 5);
        accessTree[6] = new Node(new int[]{1, 1}, new int[]{10}, false, 6);
        accessTree[7] = new Node(new int[]{2, 2}, new int[]{11,12}, true, 7);
        //accessTree[4] = new BSW.Node(new int[]{2, 2}, new int[]{7,8}, true, 2);
        //accessTree[4] = new BSW.Node(4);
        //accessTree[6] = new BSW.Node(6);
       // accessTree[7] = new BSW.Node(7);
        accessTree[3] = new Node(3);
        accessTree[8] = new Node(8);
        accessTree[9] = new Node(9);
        accessTree[10] = new Node(10);
        accessTree[11] = new Node(11);
        accessTree[12] = new Node(12);

        String dir = "BSW-ABE/data/";
        String pairingParametersFileName = "BSW-ABE/a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName, 4);
        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName, 4);

        int arraySize = 13; // 设置所需大小

        // 创建Element数组
        Element[] message = new Element[arraySize];
        int[] messageRank = {3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

        // 初始化第0个元素为GT中的随机元素
        message[0] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[1] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[4] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[5] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        message[6] = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();

//        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + Arrays.toString(message));
        encrypt(pairingParametersFileName, message, messageRank, accessTree, pkFileName, ctFileName, mskFileName);

        int[] indexs = {0, 1, 4, 5, 6};
        Element[] res = Decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName, indexs);
        System.out.println("解密结果:" + Arrays.toString(res));
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }

}
