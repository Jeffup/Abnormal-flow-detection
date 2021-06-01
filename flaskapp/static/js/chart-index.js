$(document).ready(function() {
     namespace = '/capture';
     var socket = io(namespace);
     socket.emit('connect');
      //删除事件
    window.delEvents ={
        "click #del_btn":function(e,value,row)
        {
            console.log(row);
            $.ajax({
                url:'/dealalarm',
                datatype:'json',
                data:{
                    id:row.id,
                    dealtime:DateHandle()
                },
                method:'post',
                success:function (res){
                    console.log(res)
                    $("#alarm-table").bootstrapTable('remove',value={
                        field:'id',  //删除的field名
                        values:res.id //field对应的值
                    })
                }
            })
        }
    }
    $('#alarm-table').bootstrapTable({
        url: '/querydata/alarm',  // 请求数据源的路由
        dataType: "json",
        pagination: true, //前端处理分页
        singleSelect: false,//是否只能单选
        search: false, //显示搜索框，此搜索是客户端搜索，不会进服务端，所以，个人感觉意义不大
        // toolbar: '#toolbar', //工具按钮用哪个容器
        striped: true, //是否显示行间隔色
        cache: false, //是否使用缓存，默认为true，所以一般情况下需要设置一下这个属性（*）
        pageNumber: 1, //初始化加载第10页，默认第一页
        pageSize: 10, //每页的记录行数（*）
        pageList: [10, 20, 50, 100], //可供选择的每页的行数（*）
        minimumCountColumns: 2, //当列数小于此值时，将隐藏内容列下拉框
        sidePagination: "client", //分页方式：client客户端分页，server服务端分页（*）
        // showRefresh: true, //显示刷新按钮
        sortable: true,                     //是否启用排序
        sortOrder: "desc",                   //排序方式
        sortName:'time',
        //得到查询的参数
        queryParams : function (params) {
            //这里的键的名字和控制器的变量名必须一直，这边改动，控制器也需要改成一样的
            var temp = {
                // rows: params.limit,                         //页面大小
                // page: (params.offset / params.limit) + 1,   //页码
                sort: params.sort,      //排序列名
                sortOrder: params.order ,//排位命令（desc，asc）
            };
            return temp;
        },
        responseHandler: function (res) {
            // 对返回参数进行处理
            return {
                "total": res.total,
                "rows": res.rows,
            };
        },
        columns: [{
            field: 'id',
            title: '',
            visible: false   //这一列隐藏
        },{
            field: 'ip',
            title: '攻击者',
            formatter: linkFormatter  ////连接字段格式化
        }, {
            field: 'time',
            title: '攻击时间',
        }, {
            field: 'description',
            title: '攻击描述',
        },  {
            field: 'del',
            title: '处理',
            width: 100,
            align: 'center',
            valign: 'middle',
            events:delEvents,
            formatter:delFunction
        },
        ],
    })

    function delFunction(value,row,index){
            return [
                '<button type="button" class="btn btn-primary" id="del_btn">处理</button>'
            ].join('');
        }

    //连接字段格式化
    function linkFormatter(value, row, index) {
        return "<a href='ipdetail?ip=" + value + "' title='单击打开连接' target='_blank'>" + value + "</a>";
    }

     //可将  var  time = new date();转换成 2016-08-03 18:30:00 格式//消除浏览器之间差异
    function DateHandle() {
        var objDate = new Date(); //创建一个日期对象表示当前时间
        var year = objDate.getFullYear();   //四位数字年
        var month = objDate.getMonth() + 1; //getMonth()返回的月份是从0开始的，还要加1
        var date = objDate.getDate();
        var hours = objDate.getHours();
        var minutes = objDate.getMinutes();
        var seconds = objDate.getSeconds();
        var date = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds;
        return date;
    }

    var flowchart = echarts.init(document.getElementById('flowchart'));
    var flowoption ={
        title: {
            text: '24小时流量监控图',//图片标题
        },
        legend:{
            icon:'rect',//标记图标，方形
        },
        tooltip: { //focus显示内容
            trigger: 'axis',
            formatter: function (params) {
                var tmpparams = params[1];
                params = params[0];
                if(tmpparams)
                {
                    return params.value[0] + '</br>'+params.seriesName+':' + params.value[1] + "kb/s"+'</br>'+tmpparams.seriesName+':' + tmpparams.value[1] + "kb/s";
                }
                return params.value[0] + '</br>'+params.seriesName+':' + params.value[1] + "kb/s";
            },
            axisPointer: {
                animation: false
            },
        },
        xAxis: { //x轴,类型为日期格式，故在数据中添加了一个24小时的数组，以调整x坐标系显示数据
            name:'时间',
            nameGap:30,
            nameTextStyle:{
                padding:[15,0,0,0],
                fontSize:14,
            },
            type: 'time',
            maxInterval: 3600*2*1000,
            min:'2021-05-13 16:45:40',
            max: '',
            splitLine: { //显示分割线
                show: false
            },
        },
        yAxis: { //y轴，添加留白策略数据变多时y轴突然拉的比较长
            name:'bits per second(kb/s)',
            nameLocation:'center',
            nameGap:30,
            type: 'value',
            min:0,
            // boundaryGap: [0, '30%'],//坐标轴两边留白策略
            splitLine: {
                show: false
            }
        },
        dataZoom: [	//局部显示插件
            {
            start: 0,                               //数据窗口范围的起始百分比,表示%
            end: 100,
            type: 'slider',                          //slider表示有滑动块的，inside表示内置的
            backgroundColor:"rgb(252,252,252)",
            fillerColor:"rgba(167,183,204,0.5)",     //选中范围的填充颜色。
            showDataShadow: true,	 //是否显示数据阴影
            orient:"horizontal",     //缺省情况控制横向数轴还是纵向数轴。'horizontal'：水平|x'vertical'：竖直|y。
            height:20,
            bottom:5,
            },{
            type: 'slider',
            orient:"vertical",
            showDataShadow: false,
            width:20,
            }
            ],
        series: [{	//数据
            name: '入口网速',
            type: 'line',
            step:true, //是否支持骤变，false有段数据为空时为渐变
            showSymbol: false,
            hoverAnimation: false,
            data: [
                // ['2021-05-13 16:45:40',10],
                // ['2021-05-13 16:45:41',15],
                // ['2021-05-13 16:45:42',12]
            ],
            areaStyle: {},
            lineStyle:{
                opacity:0,
            },
            itemStyle:{
                color:'rgb(0,204,0)',
            },

        },
        {
            name: '出口网速',
            type: 'line',
            showSymbol: false,
            hoverAnimation: false,
            data:  [], // ['2021-05-13 16:45:40',10],
            // lineStyle:{
            // 	opacity:0.7,
            // 	color:'rgb(0,0,225)'
            // },
            itemStyle:{
                opacity:0.7,
                color:'rgb(0,0,225)',
            }
        },
        {
            type: 'line',
            tooltip:{trigger:'none'},
            // data:[['2021-05-13 16:45:40',-1],['2021-05-13 16:45:42',-1]],//数据格式[[2019-07-04 15:20:12,-1],[2019-07-05 15:20:12,-1]]
            data:[]
        }]
    };
    flowchart.setOption(flowoption);

    socket.on('computer_msg', function(msg) {
         console.log(msg);
         flowoption.xAxis.min=msg['time'][0][0];
         // flowoption.xAxis.max=msg['time'][1][0];
         flowoption.series[2].data=msg['time'];
         flowchart.setOption(flowoption);
     // $('#log').append('<br>' + $('<div/>').text('Received #' + msg.count + ': ' + msg.data).html());
    });
    socket.on('new_message', function (data){
        console.log(data['resdata'].id)
        var ops=$('#alarm-table').bootstrapTable('getOptions');
        var opsdata=ops.data
        //  $("#alarm-table").bootstrapTable('remove',value={
        //     field:'id',  //删除的field名
        //     values:data['resdata'].id //field对应的值
        // });
        $("#alarm-table").bootstrapTable('append', data['resdata']);

    })
    socket.on('com_infomation', function (data){
         // console.log(data['cpu']);
         $("#cpuinfo").text(data['cpu']+'%');
         $("#diskinfo").text(data['disk']+'%');
         $("#meminfo").text(data['mem']+'%');
         flowoption.series[0].data.push(data['in_speed']);// in speed
         flowoption.series[1].data.push(data['out_speed']);
         flowoption.xAxis.max=data['in_speed'][0];
         flowchart.setOption(flowoption);
    })

});


