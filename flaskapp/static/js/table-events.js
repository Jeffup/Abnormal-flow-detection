
var protocolchart = echarts.init(document.getElementById('protocalchart'));
var attackipchart = echarts.init(document.getElementById('attackipchart'));

var protocoloption = {
    title : {
        text: '常见协议流量统计',
        x:'center'
    },
    tooltip: {
        show: true
    },
    calculable : true,
    xAxis : [
        {
            type : 'category',
            name : '协议类型',
            boundaryGap : true,
            data : []//"IP","TCP","UDP","ARP","ICMP","DNS","HTTP","HTTPS","Others"
        }
    ],
    yAxis : [
        {
            type : 'value',
            name : '协议数据包总流量'
        }
    ],
    series : [
        {
            "name":"协议数据包总流量",
            "type":"bar",
            itemStyle:{
                normal:{
                    label:{show:true},
                    color:'#87cefa' //图例颜色设置
                    },
                emphasis:{label:{show:true}}
                    },
            "data":[],
        }
    ]
};
var attackipoption = {
    title : {
        text: '攻击统计',
    },
    tooltip : {
        trigger: 'axis'
    },
    calculable : true,
    xAxis : [
        {
            type : 'value',
            name : '攻击次数'
        }
    ],
    yAxis : [
        {
            type : 'category',
            name : '访问IP',
            data : []
        }
    ],
     grid: { // 控制图的大小，调整下面这些值就可以
          x: 100,
     },
    series : [
        {
            name:'攻击次数',
            type:'bar',
            itemStyle:{
                normal:{
                    label:{show:true},
                    color:'#6495ed' //图例颜色设置
                    },
                emphasis:{label:{show:true}}
                    },
            data:[]
        }
    ]
};




//1.初始化Table
$('#events-table').bootstrapTable({
    url: '/querydata/events',  // 请求数据源的路由
    dataType: "json",
    pagination: true, //前端处理分页
    singleSelect: false,//是否只能单选
    search: false, //显示搜索框，此搜索是客户端搜索，不会进服务端，所以，个人感觉意义不大
    toolbar: '#toolbar', //工具按钮用哪个容器
    striped: true, //是否显示行间隔色
    cache: false, //是否使用缓存，默认为true，所以一般情况下需要设置一下这个属性（*）
    pageNumber: 1, //初始化加载第10页，默认第一页
    pageSize: 10, //每页的记录行数（*）
    pageList: [10, 20, 50, 100], //可供选择的每页的行数（*）
    sidePagination: "server", //分页方式：client客户端分页，server服务端分页（*）
    strictSearch: false,//设置为 true启用 全匹配搜索，false为模糊搜索
    showColumns: true, //显示内容列下拉框
    showRefresh: true, //显示刷新按钮
    minimumCountColumns: 2, //当列数小于此值时，将隐藏内容列下拉框
    cardView: false, //是否显示详细视图
    detailView: true, //是否显示父子表，设置为true可以显示详细页面模式,在每行最前边显示+号
    detailFormatter:"detailFormatter",  //显示详细数据包RAW字段处理函数

    sortable: true,                     //是否启用排序
    sortOrder: "desc",                   //排序方式
    sortName:'time',
    //得到查询的参数
    queryParams : function (params) {
        //这里的键的名字和控制器的变量名必须一直，这边改动，控制器也需要改成一样的
        console.log($("#attacktype").val());
        var temp = {
            rows: params.limit,                         //页面大小
            page: (params.offset / params.limit) + 1,   //页码
            sort: params.sort,      //排序列名
            sortOrder: params.order ,//排位命令（desc，asc）

            attacktype: $("#attacktype").val(),
            startdate: $("#startdate").val(),
            enddate: $("#enddate").val(),
            detail: $("#detail").val(),

        };
        return temp;
    },
    responseHandler: function (res) {
        // 对返回参数进行处理
        $("#sendatacount").text(res.sendatacount);
        $("#ipcount").text(res.ipcount);
        $("#attackcount").text(res.attackcount);
        $("#flowcount").text(res.flowcount);

        console.log(res)
        // var res2 = Object.keys(dict).sort(function(a,b){ return dict[a]-dict[b];});
        //getWordCnt(res.rows, 'ip');
        protocoldata = res.protocoldata;
        protocoloption.xAxis[0].data=Object.keys(protocoldata);
        protocoloption.series[0].data=Object.values(protocoldata);
        protocolchart.setOption(protocoloption);

        attackipdata = res.attackipdata;
        attackipoption.yAxis[0].data=Object.keys(attackipdata);
        attackipoption.series[0].data=Object.values(attackipdata);
        attackipchart.setOption(attackipoption);

        return {
            "total": res.total,
            "rows": res.rows,
        };
    },
    columns: [{
        field: 'ip',
        title: '攻击者',
        formatter: linkFormatter  ////连接字段格式化
    }, {
        field: 'first_time',
        title: '开始攻击时间',
    }, {
        field: 'last_time',
        title: '最近攻击时间',
    },{
        field: 'time',
        title: '此次攻击时间',
    }, {
        field: 'attacktype',
        title: '攻击类型',
    }, {
        field: 'description',
        title: '攻击描述',
        visible: false   //这一列隐藏
    }, {
        field: 'detail',
        title: '详情',
        visible: false   //这一列隐藏
    }, ],
})
//显示详细数据包RAW字段
function detailFormatter(index, row) {
    var html = [];
    html.push('<p><b>' + '攻击描述' + ':</b> ' + row['description'] + '</p>')
    html.push('<p><b>' + '详情' + ':</b> ' + row['detail'] + '</p>')
    return html.join('');
}

//连接字段格式化(invaild)
function linkFormatter(value, row, index) {
    return "<a href='ipdetail?ip=" + value + "' title='单击打开连接' target='_blank'>" + value + "</a>";
}

//统计相同值的数目
function getWordCnt(data, column){
    var obj = {};
    for(var i= 0, l = data.length; i< l; i++){
        var item = data[i][column];
        obj[item] = (obj[item] +1 ) || 1;
    }
    return obj;
}


//2.初始化Button的点击事件
$(document).on('click', "#queryButton",function(){
    $('#events-table').bootstrapTable('refresh');
});
$(document).on('click', "#cleanButton",function(){
    $("#attacktype").val('');
    $('#attacktype').empty();
    $("#startdate").val('');
    $("#enddate").val('');
    $("#detail").val('');
    $('#events-table').bootstrapTable('refresh');
});
