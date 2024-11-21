package CR_FH_CPABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Node {
    // gate用两个数(t,n)表示，n表示子节点个数, t表示门限值
    // 如果是叶子节点，则为null
    public int[] gate;
    // children表示内部节点，此字段为子节点索引列表
    // 如果是叶子节点，则为null
    public int[] children;
    // att表示属性值，
    // 如果是内部节点，此字段null
    public int att;
    // 索引
    public int index;
    // 是否为转移节点
    public Boolean isTran;
    // 对应的秘密值
    public Element secretShare;
    // 记录每个节点的父节点, 便于转移
    public int father;

    // 用于秘密恢复，表示此节点是否可以恢复
    public boolean valid;
    //内部节点的构造方法
    public Node(int[] gate, int[] children, Boolean isTran, int index, int father) {
        this.gate = gate;
        this.children = children;
        this.isTran = isTran;
        this.index = index;
        this.father = father;
    }
    // 叶子节点的构造方法
    public Node(int att){
        this.att = att;
    }
    public boolean isLeaf() {
        return this.children==null ? true : false;
    }
    @Override
    public String toString() {
        if (this.isLeaf()){
            return Integer.toString(this.att);
        }
        else {
            return Arrays.toString(this.gate) + " " + this.index;
        }
    }
}
