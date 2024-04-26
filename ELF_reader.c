#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        exit(0);
    }
    FILE *fp;
    Elf64_Ehdr elf_header;
    fp = fopen(argv[2], "r");
    if (fp == NULL)
    {
        exit(0);
    }
    int readfile;
    readfile = fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);
    if (readfile == 0)
    {
        exit(0);
    } //无论如何，先去读文件头
    if (!strcmp(argv[1], "-h"))
    { //-h展示文件头
        if (elf_header.e_ident[0] == 0x7F || elf_header.e_ident[1] == 'E')
        {
            printf("头标志: ");
            for (int x = 0; x < 16; x++)
            {
                printf("%02x ", elf_header.e_ident[x]);
            }
            printf("\n");
            char *file_type[4] = {"Null", "可重定位文件", "可执行文件", "共享目标文件"};
            printf("文件类型: \t\t%s\n", file_type[elf_header.e_type]);
            printf("运行平台: \t\t%hx\n", elf_header.e_machine);
            printf("入口虚拟RVA: \t\t0x%lx\n", elf_header.e_entry);
            printf("程序头文件偏移: \t%ld(bytes)\n", elf_header.e_phoff);
            printf("节头表文件偏移: \t%ld(bytes)\n", elf_header.e_shoff);
            printf("ELF文件头大小: \t\t%d\n", elf_header.e_ehsize);
            printf("ELF程序头大小: \t\t%d\n", elf_header.e_phentsize);
            printf("ELF程序头表计数: \t%d\n", elf_header.e_phnum);
            printf("ELF节头表大小: \t\t%d\n", elf_header.e_shentsize);
            printf("ELF节头表计数: \t\t%d\n", elf_header.e_shnum);
            printf("字符串表索引节头: \t%d\n", elf_header.e_shstrndx);
        }
    }
    Elf64_Shdr *shdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum); //准备空间
    fseek(fp, elf_header.e_shoff, SEEK_SET);                                          //找到段表所在位置
    fread(shdr, sizeof(Elf64_Shdr) * elf_header.e_shnum, 1, fp);                      //读进来
    rewind(fp);                                                                       //偏移指针归零
    fseek(fp, shdr[elf_header.e_shstrndx].sh_offset, SEEK_SET);                       //找到段表字符串表
    char shstrtab[shdr[elf_header.e_shstrndx].sh_size];                               //为字符串表准备空间
    char *names = shstrtab;                                                           //名字指针，为下面做准备
    fread(shstrtab, shdr[elf_header.e_shstrndx].sh_size, 1, fp);                      //读进来
    rewind(fp);
 
    if (!strcmp(argv[1], "-S"))
    { //-S
        int shnum, x;
        printf("[Num]\t节类型\t\tflag\t\t节地址\t节偏移\t节大小\t节的名称\n");
        for (shnum = 1; shnum < elf_header.e_shnum; shnum++)
        {
            char *type[12] = {"无效段\t\t", "程序段\t\t", "符号表\t\t", "字符串表\t", "重定位表\t", "符号哈希表\t", "动态链接信息\t", "提示行信息\t", "无内容\t\t", "重定位信息\t", "保留\t\t", "动态链接符号表\t"};
            char *flag[8] = {"Null\t\t", "可写\t\t", "ALLOC\t\t", "可写&ALLOC\t", "可执行\t\t", "可写&可执行\t", "ALLOC&可执行\t", "可写&执行&ALLOC\t"};
            names = shstrtab + shdr[shnum].sh_name;
            printf("[%02d]\t", shnum);
            if (shdr[shnum].sh_type < 12)
                printf("%s", type[shdr[shnum].sh_type]);
            else
                printf("gnu相关\t\t");
            if (shdr[shnum].sh_flags < 8)
                printf("%s", flag[shdr[shnum].sh_flags]);
            else
                printf("我也不知道\t"); //跑的时候发现有的不太对劲，但是我也不知道那是啥，没查到
            printf("%lx\t%lx\t%lx\t%s\n", shdr[shnum].sh_addr, shdr[shnum].sh_offset, shdr[shnum].sh_size, names);
        }
    }
    Elf64_Sym* Symbol=NULL;
    char *strtab = NULL;
    char *dynstrtab=NULL;
        if(!strcmp(argv[1],"-s")){
            int shnum;
            int temp;
            for(shnum=1;shnum<elf_header.e_shnum;shnum++){
                if (shdr[shnum].sh_type != 3)
                    continue;
                if (!strcmp(shstrtab + shdr[shnum].sh_name, ".shstrtab"))
                    continue;
                if(!strcmp(shstrtab + shdr[shnum].sh_name, ".strtab")){
                    strtab = (char *)malloc(sizeof(char) * shdr[shnum].sh_size);
                    if(strtab==NULL){
                    printf("malloc error");
                    return 0;
                    }
                    fseek(fp, shdr[shnum].sh_offset, SEEK_SET);
                    temp=fread(strtab, shdr[shnum].sh_size, 1, fp); 
                    if(temp==0){
                    printf("fread eroor");
                    return 0;
                    }
                    rewind(fp);
                }
                if(!strcmp(shstrtab + shdr[shnum].sh_name, ".dynstr")){
                    dynstrtab=(char*)malloc(sizeof(char)*shdr[shnum].sh_size);
                    if(dynstrtab==NULL){
                    printf("malloc error");
                    return 0;
                    }
                    fseek(fp, shdr[shnum].sh_offset, SEEK_SET);
                    temp=fread(dynstrtab, shdr[shnum].sh_size, 1, fp); 
                    if(temp==0){
                    printf("fread eroor");
                    return 0;
                    }
                    rewind(fp);
                }
          	}                                                //目前检测str正常
            if(strtab==NULL){
            printf("没找到字符串表");
            return 0;
            }
            for(shnum=1;shnum<elf_header.e_shnum;shnum++){
                char*Binding[3]={"LOCAL","GLOBAL","WEAK"};
                char*type[5]={"未知","变量","函数","段","文件"};
                if(shdr[shnum].sh_type!=2&&shdr[shnum].sh_type!=11)continue;
                if(shdr[shnum].sh_type==2){  //如果是普通的符号段
                    fseek(fp, shdr[shnum].sh_offset, SEEK_SET);
                    printf("符号表偏移:0x%lx\t",shdr[shnum].sh_offset);
                    Symbol=(Elf64_Sym*)malloc(sizeof(char)*shdr[shnum].sh_size);
                    temp=fread(Symbol, shdr[shnum].sh_size, 1, fp); 
                    if(temp==0){
                    printf("fread eroor");
                    return 0;
                    }
                    rewind(fp);
                    printf("表名：%s\n",shstrtab + shdr[shnum].sh_name);
                    printf("  Idx:   VALUE:  SIZE:  Type:   Bind:\tSHNDX:\tNAME:\n");
                    int num=shdr[shnum].sh_size/sizeof(Elf64_Sym);
                    for(int i=1;i<num;i++){
                    printf("  %3d : ",i);
                    printf("  0x%-8lx%-7lx",Symbol[i].st_value,Symbol[i].st_size);
                    printf("%s\t %s\t",type[Symbol[i].st_info&0xF],Binding[Symbol[i].st_info>>4]);
                    printf("%d\t%s\n",Symbol[i].st_shndx,strtab+Symbol[i].st_name);
                    }
                }
                else{//动态链接的符号段
                    fseek(fp, shdr[shnum].sh_offset, SEEK_SET);
                    printf("符号表偏移:0x%lx\t",shdr[shnum].sh_offset);
                    Elf64_Sym* DynSymbol=(Elf64_Sym*)malloc(sizeof(char)*shdr[shnum].sh_size);
                    temp=fread(DynSymbol, shdr[shnum].sh_size, 1, fp);
                    if(temp==0){
                    printf("fread eroor");
                    return 0;
                    } 
                    rewind(fp);
                    printf("表名：%s\n",shstrtab + shdr[shnum].sh_name);
                    printf("  Idx:   VALUE:  SIZE:  Type:   Bind:\tSHNDX:\tNAME:\n");
                    int num=shdr[shnum].sh_size/sizeof(Elf64_Sym);
                    for(int i=1;i<num;i++){
                    printf("  %3d : ",i);
                    printf("  0x%-8lx%-7lx",DynSymbol[i].st_value,DynSymbol[i].st_size);
                    printf("%s\t %s\t",type[DynSymbol[i].st_info&0xF],Binding[DynSymbol[i].st_info>>4]);
                    printf("%d\t%s\n",DynSymbol[i].st_shndx,dynstrtab+DynSymbol[i].st_name);
                    }
                }
            }
          }
          Elf64_Phdr *Phdr = NULL;
    if (!strcmp(argv[1], "-l"))
    {
        int size = elf_header.e_phentsize; //先读程序头表
        Phdr = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) *elf_header.e_phnum );
        fseek(fp, elf_header.e_phoff, SEEK_SET);
        int temp = fread(Phdr, sizeof(Elf64_Phdr) *elf_header.e_phnum, 1, fp);
        if (temp == 0)
        {
            printf("fread eroor");
            return 0;
        }
        printf("文件类型：");
        switch (elf_header.e_type)
        {
        case 0:
            printf(" No file type\n");
            return 0;
        case 1:
            printf(" Relocatable file\n");
            return 0;
        case 2:
            printf(" Executable file\n");
            break;
        case 3:
            printf(" Shared object file\n");
            break;
        case 4:
            printf(" Core file\n");
            break;
        default:
            printf(" ERROR\n");
        }
        printf("入口点位置 0X%0lX\n", elf_header.e_entry);
        printf("共有 %d 程序头, 偏移位置 %lu\n", elf_header.e_phnum, elf_header.e_phoff);
        printf("Program Headers:\n");
        printf(" %-16s %-16s %-16s %-16s", "Type", "Offset", "VirtAddr", "PhysAddr");
        printf(" %-16s %-16s %-16s %-6s\n", "FileSiz", "MemSiz", "Flags", "Align");
        int i;
        for (i = 0; i < elf_header.e_phnum; i++)
        {	
            switch (Phdr[i].p_type)
            {
            case 0:
                printf("NULL\t\t");
                break;
            case 1:
                printf("LOAD\t\t");
                break;
            case 2:
                printf("DYNAMIC\t\t");
                break;
            case 3:
                printf("INTERP\t\t");
                break;
            case 4:
                printf("NOTE\t\t");
                break;
            case 5:
                printf("SHLIB\t\t");
                break;
            case 6:
                printf("PHDR\t\t");
                break;
            case 7:
                printf("TLS\t\t");
                break;
            case 8:
                printf("NUM\t\t");
            case 0x60000000:
                printf("LOOS\t\t");
                break;
            case 0x6474e550:
                printf("GNU_EH_FRAME\t");
                break;
            case 0x6474e551:
                printf("GNU_STACK\t");
                break;
            case 0x6474e552:
                printf("GNU_RELRO\t");
                break;
            case 0x6ffffffa:
                printf("LOSUNW\t\t");
                break;
            case 0x6ffffffb:
                printf("SUNWSTACK\t");
                break;
            case 0x6fffffff:
                printf("HIOS\t\t");
                break;
            case 0x70000000:
                printf("LOPROC\t\t");
                break;
            case 0x7fffffff:
                printf("PT_HIPROC\t");
                break;
             default:
             	printf("0x%x\t",Phdr[i].p_type);
            }
            printf("  %-16lx %-16lx %-16lx %-16lx %-16lx ", Phdr[i].p_offset, Phdr[i].p_vaddr, Phdr[i].p_paddr, Phdr[i].p_filesz, Phdr[i].p_memsz);
            switch (Phdr[i].p_flags)
            {
            case PF_X:
                printf("%-16s %-lX\n", " E", Phdr[i].p_align);
                break;
            case PF_W:
                printf("%-16s %-lX\n", " W ", Phdr[i].p_align);
                break;
            case PF_R:
                printf("%-16s %-lX\n", "R ", Phdr[i].p_align);
                break;
            case PF_X | PF_W:
                printf("%-16s %-lX\n", " WE", Phdr[i].p_align);
                break;
            case PF_X | PF_R:
                printf("%-16s %-lX\n", "R E", Phdr[i].p_align);
                break;
            case PF_W | PF_R:
                printf("%-16s %-lX\n", "RW ", Phdr[i].p_align);
                break;
            case PF_X | PF_R | PF_W:
                printf("%-16s %-lX\n", "RWE", Phdr[i].p_align);
                break;
            default:
                printf("\n");
                break;
            }
            if(Phdr[i].p_type==3){
            	char* temp=(char*)malloc(sizeof(char)*114514);
            	fseek(fp, Phdr[i].p_offset, SEEK_SET);
        		fread(temp, Phdr[i].p_memsz, 1, fp);
            	printf("                                 [Requesting program interpreter: %s]\n", temp);
            }
        }
        printf("-------------------------------------------------------------------\n");
          printf("Section to Segment mapping:\n");
	printf("  Segment...\n");
	for(int i=0;i<elf_header.e_phnum;++i)
    	{
        printf("   %-7d", i);
        for(int n = 0;n<elf_header.e_shnum;++n)
        {
            Elf64_Off temp = shdr[n].sh_addr + shdr[n].sh_size;
            if((shdr[n].sh_addr>Phdr[i].p_vaddr && shdr[n].sh_addr<Phdr[i].p_vaddr + Phdr[i].p_memsz)  ||
                    (temp > Phdr[i].p_vaddr && temp<=Phdr[i].p_vaddr + Phdr[i].p_memsz))
            {
                printf("%s ", (char*)(shdr[n].sh_name +shstrtab ));
            }
        }
        printf("\n");
    	}
    }
    return 0;
}
 
