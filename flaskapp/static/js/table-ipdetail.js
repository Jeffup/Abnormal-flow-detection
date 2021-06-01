// 基于准备好的dom，初始化echarts实例
var myChart = echarts.init(document.getElementById('statistic_chart'));
// 指定图表的配置项和数据
var option = {
    title: {
        text: '攻击方式/数据统计',
        left: 'center'
    },
    tooltip: {
        trigger: 'item'
    },
    legend: {
        orient: 'vertical',
        left: 'left',
    },
    series: [
        {
            name: '攻击方式及次数',
            type: 'pie',
            radius: '50%',
            data: [],
            emphasis: {
                itemStyle: {
                    shadowBlur: 10,
                    shadowOffsetX: 0,
                    shadowColor: 'rgba(85,22,22,0.5)'
                }
            }
        }
    ]
};
$('#detail-table').bootstrapTable({
    url: '/querydata/ipdetail',  // 请求数据源的路由
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
    strictSearch: false,//设置为 true启用 全匹配搜索，false为模糊搜索
    showColumns: false, //显示内容列下拉框
    showRefresh: true, //显示刷新按钮
    minimumCountColumns: 2, //当列数小于此值时，将隐藏内容列下拉框
    cardView: false, //是否显示详细视图
    detailView: true, //是否显示父子表，设置为true可以显示详细页面模式,在每行最前边显示+号
    detailFormatter:"detailFormatter",  //显示详细数据包RAW字段处理函数
    sidePagination: "server", //分页方式：client客户端分页，server服务端分页（*）
    sortable: true,                     //是否启用排序
    sortOrder: "desc",                   //排序方式
    sortName:'time',
    //得到查询的参数
    queryParams : function (params) {
    //这里的键的名字和控制器的变量名必须一直，这边改动，控制器也需要改成一样的
        var temp = {
            rows: params.limit,                         //页面大小
            page: (params.offset / params.limit) + 1,   //页码
            sort: params.sort,      //排序列名
            sortOrder: params.order ,//排位命令（desc，asc）
            queryip: $('#detail-table').attr('query_ip')
            };
            return temp;
    },
    responseHandler: function (res) {
        //模板中的统计数据填补
        $('#mac').html(res.statistic[0].mac);
        $('#first-time').html(res.statistic[0].first_time);
        $('#last-time').html(res.statistic[0].last_time);
        $('#attack-count').html(res.statistic[0].attack_count);
        option.series[0].data=[]
        for(key in res.statistic[1])
        {
            // 设置echart的数据
            option.series[0].data.push({value:res.statistic[1][key],name:key});
        }
        // console.log(option.series[0].data);
        // 使用刚指定的配置项和数据显示图表。
        myChart.setOption(option);
        // 对返回参数进行处理
        return {
            "total": res.total,
            "rows": res.rows,
        };
    },
    columns: [{
        field: 'time',
        title: '攻击时间',
        sortable: true,
    }, {
        field: 'attacktype',
        title: '攻击类型',
    }, {
        field: 'description',
        title: '攻击描述',
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
